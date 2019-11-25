#define TARGET_AARCH64 1

#define TARGET_ARM 1

#define CONFIG_USER_ONLY 1

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#define unlikely(x)   __builtin_expect(!!(x), 0)

# define QEMU_FLATTEN __attribute__((flatten))

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

#include <limits.h>

#include <assert.h>

#define G_GNUC_NORETURN                         \
  __attribute__((__noreturn__))

#define G_STRFUNC     ((const char*) (__func__))

#define G_STMT_START  do

#define G_STMT_END    while (0)

#define _GLIB_EXTERN extern

#define GLIB_AVAILABLE_IN_ALL                   _GLIB_EXTERN

typedef char   gchar;

#define G_LOG_DOMAIN    ((gchar*) 0)

#define g_assert_not_reached()          G_STMT_START { g_assertion_message_expr (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, NULL); } G_STMT_END

GLIB_AVAILABLE_IN_ALL
void    g_assertion_message_expr        (const char     *domain,
                                         const char     *file,
                                         int             line,
                                         const char     *func,
                                         const char     *expr) G_GNUC_NORETURN;

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

typedef uint8_t flag;

typedef uint16_t float16;

#define make_float16(x) (x)

enum {
    float_tininess_after_rounding  = 0,
    float_tininess_before_rounding = 1
};

enum {
    float_round_nearest_even = 0,
    float_round_down         = 1,
    float_round_up           = 2,
    float_round_to_zero      = 3,
    float_round_ties_away    = 4,
    /* Not an IEEE rounding mode: round to the closest odd mantissa value */
    float_round_to_odd       = 5,
};

enum {
    float_flag_invalid   =  1,
    float_flag_divbyzero =  4,
    float_flag_overflow  =  8,
    float_flag_underflow = 16,
    float_flag_inexact   = 32,
    float_flag_input_denormal = 64,
    float_flag_output_denormal = 128
};

typedef struct float_status {
    signed char float_detect_tininess;
    signed char float_rounding_mode;
    uint8_t     float_exception_flags;
    signed char floatx80_rounding_precision;
    /* should denormalised results go to zero and set the inexact flag? */
    flag flush_to_zero;
    /* should denormalised inputs go to zero and set the input_denormal flag? */
    flag flush_inputs_to_zero;
    flag default_nan_mode;
    /* not always used -- see snan_bit_is_one() in softfloat-specialize.h */
    flag snan_bit_is_one;
} float_status;

static inline int clz64(uint64_t val)
{
    return val ? __builtin_clzll(val) : 64;
}

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

static inline uint64_t extract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    return (value >> start) & (~0ULL >> (64 - length));
}

static inline uint64_t deposit64(uint64_t value, int start, int length,
                                 uint64_t fieldval)
{
    uint64_t mask;
    assert(start >= 0 && length > 0 && length <= 64 - start);
    mask = (~0ULL >> (64 - length)) << start;
    return (value & ~mask) | ((fieldval << start) & mask);
}

enum {
    float_muladd_negate_c = 1,
    float_muladd_negate_product = 2,
    float_muladd_negate_result = 4,
    float_muladd_halve_result = 8,
};

float16 float16_muladd(float16, float16, float16, int, float_status *status);

static inline void shift64RightJamming(uint64_t a, int count, uint64_t *zPtr)
{
    uint64_t z;

    if ( count == 0 ) {
        z = a;
    }
    else if ( count < 64 ) {
        z = ( a>>count ) | ( ( a<<( ( - count ) & 63 ) ) != 0 );
    }
    else {
        z = ( a != 0 );
    }
    *zPtr = z;

}

static inline void
 shift128RightJamming(
     uint64_t a0, uint64_t a1, int count, uint64_t *z0Ptr, uint64_t *z1Ptr)
{
    uint64_t z0, z1;
    int8_t negCount = ( - count ) & 63;

    if ( count == 0 ) {
        z1 = a1;
        z0 = a0;
    }
    else if ( count < 64 ) {
        z1 = ( a0<<negCount ) | ( a1>>count ) | ( ( a1<<negCount ) != 0 );
        z0 = a0>>count;
    }
    else {
        if ( count == 64 ) {
            z1 = a0 | ( a1 != 0 );
        }
        else if ( count < 128 ) {
            z1 = ( a0>>( count & 63 ) ) | ( ( ( a0<<negCount ) | a1 ) != 0 );
        }
        else {
            z1 = ( ( a0 | a1 ) != 0 );
        }
        z0 = 0;
    }
    *z1Ptr = z1;
    *z0Ptr = z0;

}

static inline void
 add128(
     uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1, uint64_t *z0Ptr, uint64_t *z1Ptr )
{
    uint64_t z1;

    z1 = a1 + b1;
    *z1Ptr = z1;
    *z0Ptr = a0 + b0 + ( z1 < a1 );

}

static inline void
 sub128(
     uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1, uint64_t *z0Ptr, uint64_t *z1Ptr )
{

    *z1Ptr = a1 - b1;
    *z0Ptr = a0 - b0 - ( a1 < b1 );

}

static inline void mul64To128( uint64_t a, uint64_t b, uint64_t *z0Ptr, uint64_t *z1Ptr )
{
    uint32_t aHigh, aLow, bHigh, bLow;
    uint64_t z0, zMiddleA, zMiddleB, z1;

    aLow = a;
    aHigh = a>>32;
    bLow = b;
    bHigh = b>>32;
    z1 = ( (uint64_t) aLow ) * bLow;
    zMiddleA = ( (uint64_t) aLow ) * bHigh;
    zMiddleB = ( (uint64_t) aHigh ) * bLow;
    z0 = ( (uint64_t) aHigh ) * bHigh;
    zMiddleA += zMiddleB;
    z0 += ( ( (uint64_t) ( zMiddleA < zMiddleB ) )<<32 ) + ( zMiddleA>>32 );
    zMiddleA <<= 32;
    z1 += zMiddleA;
    z0 += ( z1 < zMiddleA );
    *z1Ptr = z1;
    *z0Ptr = z0;

}

typedef enum __attribute__ ((__packed__)) {
    float_class_unclassified,
    float_class_zero,
    float_class_normal,
    float_class_inf,
    float_class_qnan,  /* all NaNs from here */
    float_class_snan,
} FloatClass;

static inline __attribute__((unused)) bool is_nan(FloatClass c)
{
    return unlikely(c >= float_class_qnan);
}

static inline __attribute__((unused)) bool is_snan(FloatClass c)
{
    return c == float_class_snan;
}

static inline __attribute__((unused)) bool is_qnan(FloatClass c)
{
    return c == float_class_qnan;
}

#define DECOMPOSED_BINARY_POINT    (64 - 2)

#define DECOMPOSED_IMPLICIT_BIT    (1ull << DECOMPOSED_BINARY_POINT)

#define DECOMPOSED_OVERFLOW_BIT    (DECOMPOSED_IMPLICIT_BIT << 1)

typedef struct {
    uint64_t frac;
    int32_t  exp;
    FloatClass cls;
    bool sign;
} FloatParts;

#define FLOAT_PARAMS(E, F)                                           \
    .exp_size       = E,                                             \
    .exp_bias       = ((1 << E) - 1) >> 1,                           \
    .exp_max        = (1 << E) - 1,                                  \
    .frac_size      = F,                                             \
    .frac_shift     = DECOMPOSED_BINARY_POINT - F,                   \
    .frac_lsb       = 1ull << (DECOMPOSED_BINARY_POINT - F),         \
    .frac_lsbm1     = 1ull << ((DECOMPOSED_BINARY_POINT - F) - 1),   \
    .round_mask     = (1ull << (DECOMPOSED_BINARY_POINT - F)) - 1,   \
    .roundeven_mask = (2ull << (DECOMPOSED_BINARY_POINT - F)) - 1

typedef struct {
    int exp_size;
    int exp_bias;
    int exp_max;
    int frac_size;
    int frac_shift;
    uint64_t frac_lsb;
    uint64_t frac_lsbm1;
    uint64_t round_mask;
    uint64_t roundeven_mask;
    bool arm_althp;
} FloatFmt;

static const FloatFmt float16_params = {
    FLOAT_PARAMS(5, 10)
};

static inline FloatParts unpack_raw(FloatFmt fmt, uint64_t raw)
{
    const int sign_pos = fmt.frac_size + fmt.exp_size;

    return (FloatParts) {
        .cls = float_class_unclassified,
        .sign = extract64(raw, sign_pos, 1),
        .exp = extract64(raw, fmt.frac_size, fmt.exp_size),
        .frac = extract64(raw, 0, fmt.frac_size),
    };
}

static inline FloatParts float16_unpack_raw(float16 f)
{
    return unpack_raw(float16_params, f);
}

static inline uint64_t pack_raw(FloatFmt fmt, FloatParts p)
{
    const int sign_pos = fmt.frac_size + fmt.exp_size;
    uint64_t ret = deposit64(p.frac, fmt.frac_size, fmt.exp_size, p.exp);
    return deposit64(ret, sign_pos, 1, p.sign);
}

static inline float16 float16_pack_raw(FloatParts p)
{
    return make_float16(pack_raw(float16_params, p));
}

static inline flag snan_bit_is_one(float_status *status)
{
#if defined(TARGET_MIPS)
    return status->snan_bit_is_one;
#elif defined(TARGET_HPPA) || defined(TARGET_UNICORE32) || defined(TARGET_SH4)
    return 1;
#else
    return 0;
#endif
}

static bool parts_is_snan_frac(uint64_t frac, float_status *status)
{
#ifdef NO_SIGNALING_NANS
    return false;
#else
    flag msb = extract64(frac, DECOMPOSED_BINARY_POINT - 1, 1);
    return msb == snan_bit_is_one(status);
#endif
}

static FloatParts parts_default_nan(float_status *status)
{
    bool sign = 0;
    uint64_t frac;

#if defined(TARGET_SPARC) || defined(TARGET_M68K)
    /* !snan_bit_is_one, set all bits */
    frac = (1ULL << DECOMPOSED_BINARY_POINT) - 1;
#elif defined(TARGET_I386) || defined(TARGET_X86_64) \
    || defined(TARGET_MICROBLAZE)
    /* !snan_bit_is_one, set sign and msb */
    frac = 1ULL << (DECOMPOSED_BINARY_POINT - 1);
    sign = 1;
#elif defined(TARGET_HPPA)
    /* snan_bit_is_one, set msb-1.  */
    frac = 1ULL << (DECOMPOSED_BINARY_POINT - 2);
#else
    /* This case is true for Alpha, ARM, MIPS, OpenRISC, PPC, RISC-V,
     * S390, SH4, TriCore, and Xtensa.  I cannot find documentation
     * for Unicore32; the choice from the original commit is unchanged.
     * Our other supported targets, CRIS, LM32, Moxie, Nios2, and Tile,
     * do not have floating-point.
     */
    if (snan_bit_is_one(status)) {
        /* set all bits other than msb */
        frac = (1ULL << (DECOMPOSED_BINARY_POINT - 1)) - 1;
    } else {
        /* set msb */
        frac = 1ULL << (DECOMPOSED_BINARY_POINT - 1);
    }
#endif

    return (FloatParts) {
        .cls = float_class_qnan,
        .sign = sign,
        .exp = INT_MAX,
        .frac = frac
    };
}

static FloatParts parts_silence_nan(FloatParts a, float_status *status)
{
#ifdef NO_SIGNALING_NANS
    __builtin_trap();__builtin_unreachable();
#elif defined(TARGET_HPPA)
    a.frac &= ~(1ULL << (DECOMPOSED_BINARY_POINT - 1));
    a.frac |= 1ULL << (DECOMPOSED_BINARY_POINT - 2);
#else
    if (snan_bit_is_one(status)) {
        return parts_default_nan(status);
    } else {
        a.frac |= 1ULL << (DECOMPOSED_BINARY_POINT - 1);
    }
#endif
    a.cls = float_class_qnan;
    return a;
}

void float_raise(uint8_t flags, float_status *status)
{
    status->float_exception_flags |= flags;
}

static int pickNaNMulAdd(FloatClass a_cls, FloatClass b_cls, FloatClass c_cls,
                         bool infzero, float_status *status)
{
#if defined(TARGET_ARM)
    /* For ARM, the (inf,zero,qnan) case sets InvalidOp and returns
     * the default NaN
     */
    if (infzero && is_qnan(c_cls)) {
        float_raise(float_flag_invalid, status);
        return 3;
    }

    /* This looks different from the ARM ARM pseudocode, because the ARM ARM
     * puts the operands to a fused mac operation (a*b)+c in the order c,a,b.
     */
    if (is_snan(c_cls)) {
        return 2;
    } else if (is_snan(a_cls)) {
        return 0;
    } else if (is_snan(b_cls)) {
        return 1;
    } else if (is_qnan(c_cls)) {
        return 2;
    } else if (is_qnan(a_cls)) {
        return 0;
    } else {
        return 1;
    }
#elif defined(TARGET_MIPS)
    if (snan_bit_is_one(status)) {
        /*
         * For MIPS systems that conform to IEEE754-1985, the (inf,zero,nan)
         * case sets InvalidOp and returns the default NaN
         */
        if (infzero) {
            float_raise(float_flag_invalid, status);
            return 3;
        }
        /* Prefer sNaN over qNaN, in the a, b, c order. */
        if (is_snan(a_cls)) {
            return 0;
        } else if (is_snan(b_cls)) {
            return 1;
        } else if (is_snan(c_cls)) {
            return 2;
        } else if (is_qnan(a_cls)) {
            return 0;
        } else if (is_qnan(b_cls)) {
            return 1;
        } else {
            return 2;
        }
    } else {
        /*
         * For MIPS systems that conform to IEEE754-2008, the (inf,zero,nan)
         * case sets InvalidOp and returns the input value 'c'
         */
        if (infzero) {
            float_raise(float_flag_invalid, status);
            return 2;
        }
        /* Prefer sNaN over qNaN, in the c, a, b order. */
        if (is_snan(c_cls)) {
            return 2;
        } else if (is_snan(a_cls)) {
            return 0;
        } else if (is_snan(b_cls)) {
            return 1;
        } else if (is_qnan(c_cls)) {
            return 2;
        } else if (is_qnan(a_cls)) {
            return 0;
        } else {
            return 1;
        }
    }
#elif defined(TARGET_PPC)
    /* For PPC, the (inf,zero,qnan) case sets InvalidOp, but we prefer
     * to return an input NaN if we have one (ie c) rather than generating
     * a default NaN
     */
    if (infzero) {
        float_raise(float_flag_invalid, status);
        return 2;
    }

    /* If fRA is a NaN return it; otherwise if fRB is a NaN return it;
     * otherwise return fRC. Note that muladd on PPC is (fRA * fRC) + frB
     */
    if (is_nan(a_cls)) {
        return 0;
    } else if (is_nan(c_cls)) {
        return 2;
    } else {
        return 1;
    }
#else
    /* A default implementation: prefer a to b to c.
     * This is unlikely to actually match any real implementation.
     */
    if (is_nan(a_cls)) {
        return 0;
    } else if (is_nan(b_cls)) {
        return 1;
    } else {
        return 2;
    }
#endif
}

static FloatParts sf_canonicalize(FloatParts part, const FloatFmt *parm,
                                  float_status *status)
{
    if (part.exp == parm->exp_max && !parm->arm_althp) {
        if (part.frac == 0) {
            part.cls = float_class_inf;
        } else {
            part.frac <<= parm->frac_shift;
            part.cls = (parts_is_snan_frac(part.frac, status)
                        ? float_class_snan : float_class_qnan);
        }
    } else if (part.exp == 0) {
        if (likely(part.frac == 0)) {
            part.cls = float_class_zero;
        } else if (status->flush_inputs_to_zero) {
            float_raise(float_flag_input_denormal, status);
            part.cls = float_class_zero;
            part.frac = 0;
        } else {
            int shift = clz64(part.frac) - 1;
            part.cls = float_class_normal;
            part.exp = parm->frac_shift - parm->exp_bias - shift + 1;
            part.frac <<= shift;
        }
    } else {
        part.cls = float_class_normal;
        part.exp -= parm->exp_bias;
        part.frac = DECOMPOSED_IMPLICIT_BIT + (part.frac << parm->frac_shift);
    }
    return part;
}

static FloatParts round_canonical(FloatParts p, float_status *s,
                                  const FloatFmt *parm)
{
    const uint64_t frac_lsb = parm->frac_lsb;
    const uint64_t frac_lsbm1 = parm->frac_lsbm1;
    const uint64_t round_mask = parm->round_mask;
    const uint64_t roundeven_mask = parm->roundeven_mask;
    const int exp_max = parm->exp_max;
    const int frac_shift = parm->frac_shift;
    uint64_t frac, inc;
    int exp, flags = 0;
    bool overflow_norm;

    frac = p.frac;
    exp = p.exp;

    switch (p.cls) {
    case float_class_normal:
        switch (s->float_rounding_mode) {
        case float_round_nearest_even:
            overflow_norm = false;
            inc = ((frac & roundeven_mask) != frac_lsbm1 ? frac_lsbm1 : 0);
            break;
        case float_round_ties_away:
            overflow_norm = false;
            inc = frac_lsbm1;
            break;
        case float_round_to_zero:
            overflow_norm = true;
            inc = 0;
            break;
        case float_round_up:
            inc = p.sign ? 0 : round_mask;
            overflow_norm = p.sign;
            break;
        case float_round_down:
            inc = p.sign ? round_mask : 0;
            overflow_norm = !p.sign;
            break;
        case float_round_to_odd:
            overflow_norm = true;
            inc = frac & frac_lsb ? 0 : round_mask;
            break;
        default:
            __builtin_trap();__builtin_unreachable();
        }

        exp += parm->exp_bias;
        if (likely(exp > 0)) {
            if (frac & round_mask) {
                flags |= float_flag_inexact;
                frac += inc;
                if (frac & DECOMPOSED_OVERFLOW_BIT) {
                    frac >>= 1;
                    exp++;
                }
            }
            frac >>= frac_shift;

            if (parm->arm_althp) {
                /* ARM Alt HP eschews Inf and NaN for a wider exponent.  */
                if (unlikely(exp > exp_max)) {
                    /* Overflow.  Return the maximum normal.  */
                    flags = float_flag_invalid;
                    exp = exp_max;
                    frac = -1;
                }
            } else if (unlikely(exp >= exp_max)) {
                flags |= float_flag_overflow | float_flag_inexact;
                if (overflow_norm) {
                    exp = exp_max - 1;
                    frac = -1;
                } else {
                    p.cls = float_class_inf;
                    goto do_inf;
                }
            }
        } else if (s->flush_to_zero) {
            flags |= float_flag_output_denormal;
            p.cls = float_class_zero;
            goto do_zero;
        } else {
            bool is_tiny = (s->float_detect_tininess
                            == float_tininess_before_rounding)
                        || (exp < 0)
                        || !((frac + inc) & DECOMPOSED_OVERFLOW_BIT);

            shift64RightJamming(frac, 1 - exp, &frac);
            if (frac & round_mask) {
                /* Need to recompute round-to-even.  */
                switch (s->float_rounding_mode) {
                case float_round_nearest_even:
                    inc = ((frac & roundeven_mask) != frac_lsbm1
                           ? frac_lsbm1 : 0);
                    break;
                case float_round_to_odd:
                    inc = frac & frac_lsb ? 0 : round_mask;
                    break;
                }
                flags |= float_flag_inexact;
                frac += inc;
            }

            exp = (frac & DECOMPOSED_IMPLICIT_BIT ? 1 : 0);
            frac >>= frac_shift;

            if (is_tiny && (flags & float_flag_inexact)) {
                flags |= float_flag_underflow;
            }
            if (exp == 0 && frac == 0) {
                p.cls = float_class_zero;
            }
        }
        break;

    case float_class_zero:
    do_zero:
        exp = 0;
        frac = 0;
        break;

    case float_class_inf:
    do_inf:
        assert(!parm->arm_althp);
        exp = exp_max;
        frac = 0;
        break;

    case float_class_qnan:
    case float_class_snan:
        assert(!parm->arm_althp);
        exp = exp_max;
        frac >>= parm->frac_shift;
        break;

    default:
        __builtin_trap();__builtin_unreachable();
    }

    float_raise(flags, s);
    p.exp = exp;
    p.frac = frac;
    return p;
}

static FloatParts float16a_unpack_canonical(float16 f, float_status *s,
                                            const FloatFmt *params)
{
    return sf_canonicalize(float16_unpack_raw(f), params, s);
}

static FloatParts float16_unpack_canonical(float16 f, float_status *s)
{
    return float16a_unpack_canonical(f, s, &float16_params);
}

static float16 float16a_round_pack_canonical(FloatParts p, float_status *s,
                                             const FloatFmt *params)
{
    return float16_pack_raw(round_canonical(p, s, params));
}

static float16 float16_round_pack_canonical(FloatParts p, float_status *s)
{
    return float16a_round_pack_canonical(p, s, &float16_params);
}

static FloatParts pick_nan_muladd(FloatParts a, FloatParts b, FloatParts c,
                                  bool inf_zero, float_status *s)
{
    int which;

    if (is_snan(a.cls) || is_snan(b.cls) || is_snan(c.cls)) {
        s->float_exception_flags |= float_flag_invalid;
    }

    which = pickNaNMulAdd(a.cls, b.cls, c.cls, inf_zero, s);

    if (s->default_nan_mode) {
        /* Note that this check is after pickNaNMulAdd so that function
         * has an opportunity to set the Invalid flag.
         */
        which = 3;
    }

    switch (which) {
    case 0:
        break;
    case 1:
        a = b;
        break;
    case 2:
        a = c;
        break;
    case 3:
        return parts_default_nan(s);
    default:
        __builtin_trap();__builtin_unreachable();
    }

    if (is_snan(a.cls)) {
        return parts_silence_nan(a, s);
    }
    return a;
}

static FloatParts muladd_floats(FloatParts a, FloatParts b, FloatParts c,
                                int flags, float_status *s)
{
    bool inf_zero = ((1 << a.cls) | (1 << b.cls)) ==
                    ((1 << float_class_inf) | (1 << float_class_zero));
    bool p_sign;
    bool sign_flip = flags & float_muladd_negate_result;
    FloatClass p_class;
    uint64_t hi, lo;
    int p_exp;

    /* It is implementation-defined whether the cases of (0,inf,qnan)
     * and (inf,0,qnan) raise InvalidOperation or not (and what QNaN
     * they return if they do), so we have to hand this information
     * off to the target-specific pick-a-NaN routine.
     */
    if (is_nan(a.cls) || is_nan(b.cls) || is_nan(c.cls)) {
        return pick_nan_muladd(a, b, c, inf_zero, s);
    }

    if (inf_zero) {
        s->float_exception_flags |= float_flag_invalid;
        return parts_default_nan(s);
    }

    if (flags & float_muladd_negate_c) {
        c.sign ^= 1;
    }

    p_sign = a.sign ^ b.sign;

    if (flags & float_muladd_negate_product) {
        p_sign ^= 1;
    }

    if (a.cls == float_class_inf || b.cls == float_class_inf) {
        p_class = float_class_inf;
    } else if (a.cls == float_class_zero || b.cls == float_class_zero) {
        p_class = float_class_zero;
    } else {
        p_class = float_class_normal;
    }

    if (c.cls == float_class_inf) {
        if (p_class == float_class_inf && p_sign != c.sign) {
            s->float_exception_flags |= float_flag_invalid;
            return parts_default_nan(s);
        } else {
            a.cls = float_class_inf;
            a.sign = c.sign ^ sign_flip;
            return a;
        }
    }

    if (p_class == float_class_inf) {
        a.cls = float_class_inf;
        a.sign = p_sign ^ sign_flip;
        return a;
    }

    if (p_class == float_class_zero) {
        if (c.cls == float_class_zero) {
            if (p_sign != c.sign) {
                p_sign = s->float_rounding_mode == float_round_down;
            }
            c.sign = p_sign;
        } else if (flags & float_muladd_halve_result) {
            c.exp -= 1;
        }
        c.sign ^= sign_flip;
        return c;
    }

    /* a & b should be normals now... */
    assert(a.cls == float_class_normal &&
           b.cls == float_class_normal);

    p_exp = a.exp + b.exp;

    /* Multiply of 2 62-bit numbers produces a (2*62) == 124-bit
     * result.
     */
    mul64To128(a.frac, b.frac, &hi, &lo);
    /* binary point now at bit 124 */

    /* check for overflow */
    if (hi & (1ULL << (DECOMPOSED_BINARY_POINT * 2 + 1 - 64))) {
        shift128RightJamming(hi, lo, 1, &hi, &lo);
        p_exp += 1;
    }

    /* + add/sub */
    if (c.cls == float_class_zero) {
        /* move binary point back to 62 */
        shift128RightJamming(hi, lo, DECOMPOSED_BINARY_POINT, &hi, &lo);
    } else {
        int exp_diff = p_exp - c.exp;
        if (p_sign == c.sign) {
            /* Addition */
            if (exp_diff <= 0) {
                shift128RightJamming(hi, lo,
                                     DECOMPOSED_BINARY_POINT - exp_diff,
                                     &hi, &lo);
                lo += c.frac;
                p_exp = c.exp;
            } else {
                uint64_t c_hi, c_lo;
                /* shift c to the same binary point as the product (124) */
                c_hi = c.frac >> 2;
                c_lo = 0;
                shift128RightJamming(c_hi, c_lo,
                                     exp_diff,
                                     &c_hi, &c_lo);
                add128(hi, lo, c_hi, c_lo, &hi, &lo);
                /* move binary point back to 62 */
                shift128RightJamming(hi, lo, DECOMPOSED_BINARY_POINT, &hi, &lo);
            }

            if (lo & DECOMPOSED_OVERFLOW_BIT) {
                shift64RightJamming(lo, 1, &lo);
                p_exp += 1;
            }

        } else {
            /* Subtraction */
            uint64_t c_hi, c_lo;
            /* make C binary point match product at bit 124 */
            c_hi = c.frac >> 2;
            c_lo = 0;

            if (exp_diff <= 0) {
                shift128RightJamming(hi, lo, -exp_diff, &hi, &lo);
                if (exp_diff == 0
                    &&
                    (hi > c_hi || (hi == c_hi && lo >= c_lo))) {
                    sub128(hi, lo, c_hi, c_lo, &hi, &lo);
                } else {
                    sub128(c_hi, c_lo, hi, lo, &hi, &lo);
                    p_sign ^= 1;
                    p_exp = c.exp;
                }
            } else {
                shift128RightJamming(c_hi, c_lo,
                                     exp_diff,
                                     &c_hi, &c_lo);
                sub128(hi, lo, c_hi, c_lo, &hi, &lo);
            }

            if (hi == 0 && lo == 0) {
                a.cls = float_class_zero;
                a.sign = s->float_rounding_mode == float_round_down;
                a.sign ^= sign_flip;
                return a;
            } else {
                int shift;
                if (hi != 0) {
                    shift = clz64(hi);
                } else {
                    shift = clz64(lo) + 64;
                }
                /* Normalizing to a binary point of 124 is the
                   correct adjust for the exponent.  However since we're
                   shifting, we might as well put the binary point back
                   at 62 where we really want it.  Therefore shift as
                   if we're leaving 1 bit at the top of the word, but
                   adjust the exponent as if we're leaving 3 bits.  */
                shift -= 1;
                if (shift >= 64) {
                    lo = lo << (shift - 64);
                } else {
                    hi = (hi << shift) | (lo >> (64 - shift));
                    lo = hi | ((lo << shift) != 0);
                }
                p_exp -= shift - 2;
            }
        }
    }

    if (flags & float_muladd_halve_result) {
        p_exp -= 1;
    }

    /* finally prepare our result */
    a.cls = float_class_normal;
    a.sign = p_sign ^ sign_flip;
    a.exp = p_exp;
    a.frac = lo;

    return a;
}

float16 QEMU_FLATTEN float16_muladd(float16 a, float16 b, float16 c,
                                                int flags, float_status *status)
{
    FloatParts pa = float16_unpack_canonical(a, status);
    FloatParts pb = float16_unpack_canonical(b, status);
    FloatParts pc = float16_unpack_canonical(c, status);
    FloatParts pr = muladd_floats(pa, pb, pc, flags, status);

    return float16_round_pack_canonical(pr, status);
}

#define QTAILQ_ENTRY(type)                                              \
union {                                                                 \
        struct type *tqe_next;        /* next element */                \
        QTailQLink tqe_circ;          /* link for circular backwards list */ \
}

typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

typedef struct MemTxAttrs {
    /* Bus masters which don't specify any attributes will get this
     * (via the MEMTXATTRS_UNSPECIFIED constant), so that we can
     * distinguish "all attributes deliberately clear" from
     * "didn't specify" if necessary.
     */
    unsigned int unspecified:1;
    /* ARM/AMBA: TrustZone Secure access
     * x86: System Management Mode access
     */
    unsigned int secure:1;
    /* Memory access is usermode (unprivileged) */
    unsigned int user:1;
    /* Requester ID (for MSI for example) */
    unsigned int requester_id:16;
    /* Invert endianness for this page */
    unsigned int byte_swap:1;
    /*
     * The following are target-specific page-table bits.  These are not
     * related to actual memory transactions at all.  However, this structure
     * is part of the tlb_fill interface, cached in the cputlb structure,
     * and has unused bits.  These fields will be read by target-specific
     * helpers using env->iotlb[mmu_idx][tlb_index()].attrs.target_tlb_bitN.
     */
    unsigned int target_tlb_bit0 : 1;
    unsigned int target_tlb_bit1 : 1;
    unsigned int target_tlb_bit2 : 1;
} MemTxAttrs;

typedef uint64_t vaddr;

typedef struct CPUBreakpoint {
    vaddr pc;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUBreakpoint) entry;
} CPUBreakpoint;

struct CPUWatchpoint {
    vaddr vaddr;
    vaddr len;
    vaddr hitaddr;
    MemTxAttrs hitattrs;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUWatchpoint) entry;
};

struct arm_boot_info;

enum {
    M_REG_NS = 0,
    M_REG_S = 1,
    M_REG_NUM_BANKS = 2,
};

#define NUM_GTIMERS 4

typedef struct ARMGenericTimer {
    uint64_t cval; /* Timer CompareValue register */
    uint64_t ctl; /* Timer Control register */
} ARMGenericTimer;

# define ARM_MAX_VQ    16

typedef struct {
    uint64_t raw_tcr;
    uint32_t mask;
    uint32_t base_mask;
} TCR;

typedef struct ARMVectorReg {
    uint64_t d[2 * ARM_MAX_VQ] QEMU_ALIGNED(16);
} ARMVectorReg;

typedef struct ARMPredicateReg {
    uint64_t p[DIV_ROUND_UP(2 * ARM_MAX_VQ, 8)] QEMU_ALIGNED(16);
} ARMPredicateReg;

typedef struct ARMPACKey {
    uint64_t lo, hi;
} ARMPACKey;

typedef struct CPUARMState {
    /* Regs for current mode.  */
    uint32_t regs[16];

    /* 32/64 switch only happens when taking and returning from
     * exceptions so the overlap semantics are taken care of then
     * instead of having a complicated union.
     */
    /* Regs for A64 mode.  */
    uint64_t xregs[32];
    uint64_t pc;
    /* PSTATE isn't an architectural register for ARMv8. However, it is
     * convenient for us to assemble the underlying state into a 32 bit format
     * identical to the architectural format used for the SPSR. (This is also
     * what the Linux kernel's 'pstate' field in signal handlers and KVM's
     * 'pstate' register are.) Of the PSTATE bits:
     *  NZCV are kept in the split out env->CF/VF/NF/ZF, (which have the same
     *    semantics as for AArch32, as described in the comments on each field)
     *  nRW (also known as M[4]) is kept, inverted, in env->aarch64
     *  DAIF (exception masks) are kept in env->daif
     *  BTYPE is kept in env->btype
     *  all other bits are stored in their correct places in env->pstate
     */
    uint32_t pstate;
    uint32_t aarch64; /* 1 if CPU is in aarch64 state; inverse of PSTATE.nRW */

    /* Cached TBFLAGS state.  See below for which bits are included.  */
    uint32_t hflags;

    /* Frequently accessed CPSR bits are stored separately for efficiency.
       This contains all the other bits.  Use cpsr_{read,write} to access
       the whole CPSR.  */
    uint32_t uncached_cpsr;
    uint32_t spsr;

    /* Banked registers.  */
    uint64_t banked_spsr[8];
    uint32_t banked_r13[8];
    uint32_t banked_r14[8];

    /* These hold r8-r12.  */
    uint32_t usr_regs[5];
    uint32_t fiq_regs[5];

    /* cpsr flag cache for faster execution */
    uint32_t CF; /* 0 or 1 */
    uint32_t VF; /* V is the bit 31. All other bits are undefined */
    uint32_t NF; /* N is bit 31. All other bits are undefined.  */
    uint32_t ZF; /* Z set if zero.  */
    uint32_t QF; /* 0 or 1 */
    uint32_t GE; /* cpsr[19:16] */
    uint32_t thumb; /* cpsr[5]. 0 = arm mode, 1 = thumb mode. */
    uint32_t condexec_bits; /* IT bits.  cpsr[15:10,26:25].  */
    uint32_t btype;  /* BTI branch type.  spsr[11:10].  */
    uint64_t daif; /* exception masks, in the bits they are in PSTATE */

    uint64_t elr_el[4]; /* AArch64 exception link regs  */
    uint64_t sp_el[4]; /* AArch64 banked stack pointers */

    /* System control coprocessor (cp15) */
    struct {
        uint32_t c0_cpuid;
        union { /* Cache size selection */
            struct {
                uint64_t _unused_csselr0;
                uint64_t csselr_ns;
                uint64_t _unused_csselr1;
                uint64_t csselr_s;
            };
            uint64_t csselr_el[4];
        };
        union { /* System control register. */
            struct {
                uint64_t _unused_sctlr;
                uint64_t sctlr_ns;
                uint64_t hsctlr;
                uint64_t sctlr_s;
            };
            uint64_t sctlr_el[4];
        };
        uint64_t cpacr_el1; /* Architectural feature access control register */
        uint64_t cptr_el[4];  /* ARMv8 feature trap registers */
        uint32_t c1_xscaleauxcr; /* XScale auxiliary control register.  */
        uint64_t sder; /* Secure debug enable register. */
        uint32_t nsacr; /* Non-secure access control register. */
        union { /* MMU translation table base 0. */
            struct {
                uint64_t _unused_ttbr0_0;
                uint64_t ttbr0_ns;
                uint64_t _unused_ttbr0_1;
                uint64_t ttbr0_s;
            };
            uint64_t ttbr0_el[4];
        };
        union { /* MMU translation table base 1. */
            struct {
                uint64_t _unused_ttbr1_0;
                uint64_t ttbr1_ns;
                uint64_t _unused_ttbr1_1;
                uint64_t ttbr1_s;
            };
            uint64_t ttbr1_el[4];
        };
        uint64_t vttbr_el2; /* Virtualization Translation Table Base.  */
        /* MMU translation table base control. */
        TCR tcr_el[4];
        TCR vtcr_el2; /* Virtualization Translation Control.  */
        uint32_t c2_data; /* MPU data cacheable bits.  */
        uint32_t c2_insn; /* MPU instruction cacheable bits.  */
        union { /* MMU domain access control register
                 * MPU write buffer control.
                 */
            struct {
                uint64_t dacr_ns;
                uint64_t dacr_s;
            };
            struct {
                uint64_t dacr32_el2;
            };
        };
        uint32_t pmsav5_data_ap; /* PMSAv5 MPU data access permissions */
        uint32_t pmsav5_insn_ap; /* PMSAv5 MPU insn access permissions */
        uint64_t hcr_el2; /* Hypervisor configuration register */
        uint64_t scr_el3; /* Secure configuration register.  */
        union { /* Fault status registers.  */
            struct {
                uint64_t ifsr_ns;
                uint64_t ifsr_s;
            };
            struct {
                uint64_t ifsr32_el2;
            };
        };
        union {
            struct {
                uint64_t _unused_dfsr;
                uint64_t dfsr_ns;
                uint64_t hsr;
                uint64_t dfsr_s;
            };
            uint64_t esr_el[4];
        };
        uint32_t c6_region[8]; /* MPU base/size registers.  */
        union { /* Fault address registers. */
            struct {
                uint64_t _unused_far0;
#ifdef HOST_WORDS_BIGENDIAN
                uint32_t ifar_ns;
                uint32_t dfar_ns;
                uint32_t ifar_s;
                uint32_t dfar_s;
#else
                uint32_t dfar_ns;
                uint32_t ifar_ns;
                uint32_t dfar_s;
                uint32_t ifar_s;
#endif
                uint64_t _unused_far3;
            };
            uint64_t far_el[4];
        };
        uint64_t hpfar_el2;
        uint64_t hstr_el2;
        union { /* Translation result. */
            struct {
                uint64_t _unused_par_0;
                uint64_t par_ns;
                uint64_t _unused_par_1;
                uint64_t par_s;
            };
            uint64_t par_el[4];
        };

        uint32_t c9_insn; /* Cache lockdown registers.  */
        uint32_t c9_data;
        uint64_t c9_pmcr; /* performance monitor control register */
        uint64_t c9_pmcnten; /* perf monitor counter enables */
        uint64_t c9_pmovsr; /* perf monitor overflow status */
        uint64_t c9_pmuserenr; /* perf monitor user enable */
        uint64_t c9_pmselr; /* perf monitor counter selection register */
        uint64_t c9_pminten; /* perf monitor interrupt enables */
        union { /* Memory attribute redirection */
            struct {
#ifdef HOST_WORDS_BIGENDIAN
                uint64_t _unused_mair_0;
                uint32_t mair1_ns;
                uint32_t mair0_ns;
                uint64_t _unused_mair_1;
                uint32_t mair1_s;
                uint32_t mair0_s;
#else
                uint64_t _unused_mair_0;
                uint32_t mair0_ns;
                uint32_t mair1_ns;
                uint64_t _unused_mair_1;
                uint32_t mair0_s;
                uint32_t mair1_s;
#endif
            };
            uint64_t mair_el[4];
        };
        union { /* vector base address register */
            struct {
                uint64_t _unused_vbar;
                uint64_t vbar_ns;
                uint64_t hvbar;
                uint64_t vbar_s;
            };
            uint64_t vbar_el[4];
        };
        uint32_t mvbar; /* (monitor) vector base address register */
        struct { /* FCSE PID. */
            uint32_t fcseidr_ns;
            uint32_t fcseidr_s;
        };
        union { /* Context ID. */
            struct {
                uint64_t _unused_contextidr_0;
                uint64_t contextidr_ns;
                uint64_t _unused_contextidr_1;
                uint64_t contextidr_s;
            };
            uint64_t contextidr_el[4];
        };
        union { /* User RW Thread register. */
            struct {
                uint64_t tpidrurw_ns;
                uint64_t tpidrprw_ns;
                uint64_t htpidr;
                uint64_t _tpidr_el3;
            };
            uint64_t tpidr_el[4];
        };
        /* The secure banks of these registers don't map anywhere */
        uint64_t tpidrurw_s;
        uint64_t tpidrprw_s;
        uint64_t tpidruro_s;

        union { /* User RO Thread register. */
            uint64_t tpidruro_ns;
            uint64_t tpidrro_el[1];
        };
        uint64_t c14_cntfrq; /* Counter Frequency register */
        uint64_t c14_cntkctl; /* Timer Control register */
        uint32_t cnthctl_el2; /* Counter/Timer Hyp Control register */
        uint64_t cntvoff_el2; /* Counter Virtual Offset register */
        ARMGenericTimer c14_timer[NUM_GTIMERS];
        uint32_t c15_cpar; /* XScale Coprocessor Access Register */
        uint32_t c15_ticonfig; /* TI925T configuration byte.  */
        uint32_t c15_i_max; /* Maximum D-cache dirty line index.  */
        uint32_t c15_i_min; /* Minimum D-cache dirty line index.  */
        uint32_t c15_threadid; /* TI debugger thread-ID.  */
        uint32_t c15_config_base_address; /* SCU base address.  */
        uint32_t c15_diagnostic; /* diagnostic register */
        uint32_t c15_power_diagnostic;
        uint32_t c15_power_control; /* power control */
        uint64_t dbgbvr[16]; /* breakpoint value registers */
        uint64_t dbgbcr[16]; /* breakpoint control registers */
        uint64_t dbgwvr[16]; /* watchpoint value registers */
        uint64_t dbgwcr[16]; /* watchpoint control registers */
        uint64_t mdscr_el1;
        uint64_t oslsr_el1; /* OS Lock Status */
        uint64_t mdcr_el2;
        uint64_t mdcr_el3;
        /* Stores the architectural value of the counter *the last time it was
         * updated* by pmccntr_op_start. Accesses should always be surrounded
         * by pmccntr_op_start/pmccntr_op_finish to guarantee the latest
         * architecturally-correct value is being read/set.
         */
        uint64_t c15_ccnt;
        /* Stores the delta between the architectural value and the underlying
         * cycle count during normal operation. It is used to update c15_ccnt
         * to be the correct architectural value before accesses. During
         * accesses, c15_ccnt_delta contains the underlying count being used
         * for the access, after which it reverts to the delta value in
         * pmccntr_op_finish.
         */
        uint64_t c15_ccnt_delta;
        uint64_t c14_pmevcntr[31];
        uint64_t c14_pmevcntr_delta[31];
        uint64_t c14_pmevtyper[31];
        uint64_t pmccfiltr_el0; /* Performance Monitor Filter Register */
        uint64_t vpidr_el2; /* Virtualization Processor ID Register */
        uint64_t vmpidr_el2; /* Virtualization Multiprocessor ID Register */
    } cp15;

    struct {
        /* M profile has up to 4 stack pointers:
         * a Main Stack Pointer and a Process Stack Pointer for each
         * of the Secure and Non-Secure states. (If the CPU doesn't support
         * the security extension then it has only two SPs.)
         * In QEMU we always store the currently active SP in regs[13],
         * and the non-active SP for the current security state in
         * v7m.other_sp. The stack pointers for the inactive security state
         * are stored in other_ss_msp and other_ss_psp.
         * switch_v7m_security_state() is responsible for rearranging them
         * when we change security state.
         */
        uint32_t other_sp;
        uint32_t other_ss_msp;
        uint32_t other_ss_psp;
        uint32_t vecbase[M_REG_NUM_BANKS];
        uint32_t basepri[M_REG_NUM_BANKS];
        uint32_t control[M_REG_NUM_BANKS];
        uint32_t ccr[M_REG_NUM_BANKS]; /* Configuration and Control */
        uint32_t cfsr[M_REG_NUM_BANKS]; /* Configurable Fault Status */
        uint32_t hfsr; /* HardFault Status */
        uint32_t dfsr; /* Debug Fault Status Register */
        uint32_t sfsr; /* Secure Fault Status Register */
        uint32_t mmfar[M_REG_NUM_BANKS]; /* MemManage Fault Address */
        uint32_t bfar; /* BusFault Address */
        uint32_t sfar; /* Secure Fault Address Register */
        unsigned mpu_ctrl[M_REG_NUM_BANKS]; /* MPU_CTRL */
        int exception;
        uint32_t primask[M_REG_NUM_BANKS];
        uint32_t faultmask[M_REG_NUM_BANKS];
        uint32_t aircr; /* only holds r/w state if security extn implemented */
        uint32_t secure; /* Is CPU in Secure state? (not guest visible) */
        uint32_t csselr[M_REG_NUM_BANKS];
        uint32_t scr[M_REG_NUM_BANKS];
        uint32_t msplim[M_REG_NUM_BANKS];
        uint32_t psplim[M_REG_NUM_BANKS];
        uint32_t fpcar[M_REG_NUM_BANKS];
        uint32_t fpccr[M_REG_NUM_BANKS];
        uint32_t fpdscr[M_REG_NUM_BANKS];
        uint32_t cpacr[M_REG_NUM_BANKS];
        uint32_t nsacr;
    } v7m;

    /* Information associated with an exception about to be taken:
     * code which raises an exception must set cs->exception_index and
     * the relevant parts of this structure; the cpu_do_interrupt function
     * will then set the guest-visible registers as part of the exception
     * entry process.
     */
    struct {
        uint32_t syndrome; /* AArch64 format syndrome register */
        uint32_t fsr; /* AArch32 format fault status register info */
        uint64_t vaddress; /* virtual addr associated with exception, if any */
        uint32_t target_el; /* EL the exception should be targeted for */
        /* If we implement EL2 we will also need to store information
         * about the intermediate physical address for stage 2 faults.
         */
    } exception;

    /* Information associated with an SError */
    struct {
        uint8_t pending;
        uint8_t has_esr;
        uint64_t esr;
    } serror;

    /* State of our input IRQ/FIQ/VIRQ/VFIQ lines */
    uint32_t irq_line_state;

    /* Thumb-2 EE state.  */
    uint32_t teecr;
    uint32_t teehbr;

    /* VFP coprocessor state.  */
    struct {
        ARMVectorReg zregs[32];

#ifdef TARGET_AARCH64
        /* Store FFR as pregs[16] to make it easier to treat as any other.  */
#define FFR_PRED_NUM 16
        ARMPredicateReg pregs[17];
        /* Scratch space for aa64 sve predicate temporary.  */
        ARMPredicateReg preg_tmp;
#endif

        /* We store these fpcsr fields separately for convenience.  */
        uint32_t qc[4] QEMU_ALIGNED(16);
        int vec_len;
        int vec_stride;

        uint32_t xregs[16];

        /* Scratch space for aa32 neon expansion.  */
        uint32_t scratch[8];

        /* There are a number of distinct float control structures:
         *
         *  fp_status: is the "normal" fp status.
         *  fp_status_fp16: used for half-precision calculations
         *  standard_fp_status : the ARM "Standard FPSCR Value"
         *
         * Half-precision operations are governed by a separate
         * flush-to-zero control bit in FPSCR:FZ16. We pass a separate
         * status structure to control this.
         *
         * The "Standard FPSCR", ie default-NaN, flush-to-zero,
         * round-to-nearest and is used by any operations (generally
         * Neon) which the architecture defines as controlled by the
         * standard FPSCR value rather than the FPSCR.
         *
         * To avoid having to transfer exception bits around, we simply
         * say that the FPSCR cumulative exception flags are the logical
         * OR of the flags in the three fp statuses. This relies on the
         * only thing which needs to read the exception flags being
         * an explicit FPSCR read.
         */
        float_status fp_status;
        float_status fp_status_f16;
        float_status standard_fp_status;

        /* ZCR_EL[1-3] */
        uint64_t zcr_el[4];
    } vfp;
    uint64_t exclusive_addr;
    uint64_t exclusive_val;
    uint64_t exclusive_high;

    /* iwMMXt coprocessor state.  */
    struct {
        uint64_t regs[16];
        uint64_t val;

        uint32_t cregs[16];
    } iwmmxt;

#ifdef TARGET_AARCH64
    struct {
        ARMPACKey apia;
        ARMPACKey apib;
        ARMPACKey apda;
        ARMPACKey apdb;
        ARMPACKey apga;
    } keys;
#endif

#if defined(CONFIG_USER_ONLY)
    /* For usermode syscall translation.  */
    int eabi;
#endif

    struct CPUBreakpoint *cpu_breakpoint[16];
    struct CPUWatchpoint *cpu_watchpoint[16];

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    /* Fields after this point are preserved across CPU reset. */

    /* Internal CPU feature flags.  */
    uint64_t features;

    /* PMSAv7 MPU */
    struct {
        uint32_t *drbar;
        uint32_t *drsr;
        uint32_t *dracr;
        uint32_t rnr[M_REG_NUM_BANKS];
    } pmsav7;

    /* PMSAv8 MPU */
    struct {
        /* The PMSAv8 implementation also shares some PMSAv7 config
         * and state:
         *  pmsav7.rnr (region number register)
         *  pmsav7_dregion (number of configured regions)
         */
        uint32_t *rbar[M_REG_NUM_BANKS];
        uint32_t *rlar[M_REG_NUM_BANKS];
        uint32_t mair0[M_REG_NUM_BANKS];
        uint32_t mair1[M_REG_NUM_BANKS];
    } pmsav8;

    /* v8M SAU */
    struct {
        uint32_t *rbar;
        uint32_t *rlar;
        uint32_t rnr;
        uint32_t ctrl;
    } sau;

    void *nvic;
    const struct arm_boot_info *boot_info;
    /* Store GICv3CPUState to access from this struct */
    void *gicv3state;
} CPUARMState;

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

#define SIMD_MAXSZ_SHIFT   (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_MAXSZ_BITS    5

#define SIMD_DATA_SHIFT    (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

#define H1_2(x) (x)

static void do_fmla_zpzzz_h(CPUARMState *env, void *vg, uint32_t desc,
                            uint16_t neg1, uint16_t neg3)
{
    intptr_t i = simd_oprsz(desc);
    unsigned rd = extract32(desc, SIMD_DATA_SHIFT, 5);
    unsigned rn = extract32(desc, SIMD_DATA_SHIFT + 5, 5);
    unsigned rm = extract32(desc, SIMD_DATA_SHIFT + 10, 5);
    unsigned ra = extract32(desc, SIMD_DATA_SHIFT + 15, 5);
    void *vd = &env->vfp.zregs[rd];
    void *vn = &env->vfp.zregs[rn];
    void *vm = &env->vfp.zregs[rm];
    void *va = &env->vfp.zregs[ra];
    uint64_t *g = vg;

    do {
        uint64_t pg = g[(i - 1) >> 6];
        do {
            i -= 2;
            if (likely((pg >> (i & 63)) & 1)) {
                float16 e1, e2, e3, r;

                e1 = *(uint16_t *)(vn + H1_2(i)) ^ neg1;
                e2 = *(uint16_t *)(vm + H1_2(i));
                e3 = *(uint16_t *)(va + H1_2(i)) ^ neg3;
                r = float16_muladd(e1, e2, e3, 0, &env->vfp.fp_status_f16);
                *(uint16_t *)(vd + H1_2(i)) = r;
            }
        } while (i & 63);
    } while (i != 0);
}

void HELPER(sve_fnmla_zpzzz_h)(CPUARMState *env, void *vg, uint32_t desc)
{
    do_fmla_zpzzz_h(env, vg, desc, 0x8000, 0x8000);
}

