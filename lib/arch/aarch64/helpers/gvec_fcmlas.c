#define TARGET_ARM 1

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

#include <float.h>

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

#include <math.h>

typedef uint8_t flag;

typedef uint32_t float32;

#define float32_val(x) (x)

#define make_float32(x) (x)

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

float32 float32_muladd(float32, float32, float32, int, float_status *status);

static inline float32 float32_chs(float32 a)
{
    /* Note that chs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float32(float32_val(a) ^ 0x80000000);
}

static inline int float32_is_infinity(float32 a)
{
    return (float32_val(a) & 0x7fffffff) == 0x7f800000;
}

static inline int float32_is_neg(float32 a)
{
    return float32_val(a) >> 31;
}

static inline int float32_is_zero(float32 a)
{
    return (float32_val(a) & 0x7fffffff) == 0;
}

static inline int float32_is_zero_or_denormal(float32 a)
{
    return (float32_val(a) & 0x7f800000) == 0;
}

static inline bool float32_is_normal(float32 a)
{
    return (((float32_val(a) >> 23) + 1) & 0xff) >= 2;
}

static inline bool float32_is_denormal(float32 a)
{
    return float32_is_zero_or_denormal(a) && !float32_is_zero(a);
}

static inline bool float32_is_zero_or_normal(float32 a)
{
    return float32_is_normal(a) || float32_is_zero(a);
}

#define float32_zero make_float32(0)

static inline float32 float32_set_sign(float32 a, int sign)
{
    return make_float32((float32_val(a) & 0x7fffffff) | (sign << 31));
}

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

#define GEN_INPUT_FLUSH__NOCHECK(name, soft_t)                          \
    static inline void name(soft_t *a, float_status *s)                 \
    {                                                                   \
        if (unlikely(soft_t ## _is_denormal(*a))) {                     \
            *a = soft_t ## _set_sign(soft_t ## _zero,                   \
                                     soft_t ## _is_neg(*a));            \
            s->float_exception_flags |= float_flag_input_denormal;      \
        }                                                               \
    }

GEN_INPUT_FLUSH__NOCHECK(float32_input_flush__nocheck, float32)

#define GEN_INPUT_FLUSH3(name, soft_t)                                  \
    static inline void name(soft_t *a, soft_t *b, soft_t *c, float_status *s) \
    {                                                                   \
        if (likely(!s->flush_inputs_to_zero)) {                         \
            return;                                                     \
        }                                                               \
        soft_t ## _input_flush__nocheck(a, s);                          \
        soft_t ## _input_flush__nocheck(b, s);                          \
        soft_t ## _input_flush__nocheck(c, s);                          \
    }

GEN_INPUT_FLUSH3(float32_input_flush3, float32)

# define QEMU_HARDFLOAT_2F32_USE_FP 0

# define QEMU_HARDFLOAT_3F32_USE_FP 0

# define QEMU_HARDFLOAT_USE_ISINF   1

# define QEMU_NO_HARDFLOAT 0

# define QEMU_SOFTFLOAT_ATTR QEMU_FLATTEN __attribute__((noinline))

static inline bool can_use_fpu(const float_status *s)
{
    if (QEMU_NO_HARDFLOAT) {
        return false;
    }
    return likely(s->float_exception_flags & float_flag_inexact &&
                  s->float_rounding_mode == float_round_nearest_even);
}

typedef union {
    float32 s;
    float h;
} union_float32;

static inline bool f32_is_zon2(union_float32 a, union_float32 b)
{
    if (QEMU_HARDFLOAT_2F32_USE_FP) {
        /*
         * Not using a temp variable for consecutive fpclassify calls ends up
         * generating faster code.
         */
        return (fpclassify(a.h) == FP_NORMAL || fpclassify(a.h) == FP_ZERO) &&
               (fpclassify(b.h) == FP_NORMAL || fpclassify(b.h) == FP_ZERO);
    }
    return float32_is_zero_or_normal(a.s) &&
           float32_is_zero_or_normal(b.s);
}

static inline
bool f32_is_zon3(union_float32 a, union_float32 b, union_float32 c)
{
    if (QEMU_HARDFLOAT_3F32_USE_FP) {
        return (fpclassify(a.h) == FP_NORMAL || fpclassify(a.h) == FP_ZERO) &&
               (fpclassify(b.h) == FP_NORMAL || fpclassify(b.h) == FP_ZERO) &&
               (fpclassify(c.h) == FP_NORMAL || fpclassify(c.h) == FP_ZERO);
    }
    return float32_is_zero_or_normal(a.s) &&
           float32_is_zero_or_normal(b.s) &&
           float32_is_zero_or_normal(c.s);
}

static inline bool f32_is_inf(union_float32 a)
{
    if (QEMU_HARDFLOAT_USE_ISINF) {
        return isinf(a.h);
    }
    return float32_is_infinity(a.s);
}

static float _fabsf(float x) {
  union {
    float f;
    uint32_t i;
  } u = {x};
  u.i &= 0x7fffffff;
  return u.f;
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

static const FloatFmt float32_params = {
    FLOAT_PARAMS(8, 23)
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

static inline FloatParts float32_unpack_raw(float32 f)
{
    return unpack_raw(float32_params, f);
}

static inline uint64_t pack_raw(FloatFmt fmt, FloatParts p)
{
    const int sign_pos = fmt.frac_size + fmt.exp_size;
    uint64_t ret = deposit64(p.frac, fmt.frac_size, fmt.exp_size, p.exp);
    return deposit64(ret, sign_pos, 1, p.sign);
}

static inline float32 float32_pack_raw(FloatParts p)
{
    return make_float32(pack_raw(float32_params, p));
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

static FloatParts float32_unpack_canonical(float32 f, float_status *s)
{
    return sf_canonicalize(float32_unpack_raw(f), &float32_params, s);
}

static float32 float32_round_pack_canonical(FloatParts p, float_status *s)
{
    return float32_pack_raw(round_canonical(p, s, &float32_params));
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

static float32 QEMU_SOFTFLOAT_ATTR
soft_f32_muladd(float32 a, float32 b, float32 c, int flags,
                float_status *status)
{
    FloatParts pa = float32_unpack_canonical(a, status);
    FloatParts pb = float32_unpack_canonical(b, status);
    FloatParts pc = float32_unpack_canonical(c, status);
    FloatParts pr = muladd_floats(pa, pb, pc, flags, status);

    return float32_round_pack_canonical(pr, status);
}

static bool force_soft_fma;

static float internal_fmaf(float x, float y, float z);

float32 QEMU_FLATTEN
float32_muladd(float32 xa, float32 xb, float32 xc, int flags, float_status *s)
{
    union_float32 ua, ub, uc, ur;

    ua.s = xa;
    ub.s = xb;
    uc.s = xc;

    if (unlikely(!can_use_fpu(s))) {
        goto soft;
    }
    if (unlikely(flags & float_muladd_halve_result)) {
        goto soft;
    }

    float32_input_flush3(&ua.s, &ub.s, &uc.s, s);
    if (unlikely(!f32_is_zon3(ua, ub, uc))) {
        goto soft;
    }

    if (unlikely(force_soft_fma)) {
        goto soft;
    }

    /*
     * When (a || b) == 0, there's no need to check for under/over flow,
     * since we know the addend is (normal || 0) and the product is 0.
     */
    if (float32_is_zero(ua.s) || float32_is_zero(ub.s)) {
        union_float32 up;
        bool prod_sign;

        prod_sign = float32_is_neg(ua.s) ^ float32_is_neg(ub.s);
        prod_sign ^= !!(flags & float_muladd_negate_product);
        up.s = float32_set_sign(float32_zero, prod_sign);

        if (flags & float_muladd_negate_c) {
            uc.h = -uc.h;
        }
        ur.h = up.h + uc.h;
    } else {
        union_float32 ua_orig = ua;
        union_float32 uc_orig = uc;

        if (flags & float_muladd_negate_product) {
            ua.h = -ua.h;
        }
        if (flags & float_muladd_negate_c) {
            uc.h = -uc.h;
        }

        ur.h = fmaf(ua.h, ub.h, uc.h);

        if (unlikely(f32_is_inf(ur))) {
            s->float_exception_flags |= float_flag_overflow;
        } else if (unlikely(_fabsf(ur.h) <= FLT_MIN)) {
            ua = ua_orig;
            uc = uc_orig;
            goto soft;
        }
    }
    if (flags & float_muladd_negate_result) {
        return float32_chs(ur.s);
    }
    return ur.s;

 soft:
    return soft_f32_muladd(ua.s, ub.s, uc.s, flags, s);
}

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

static inline intptr_t simd_maxsz(uint32_t desc)
{
    return (extract32(desc, SIMD_MAXSZ_SHIFT, SIMD_MAXSZ_BITS) + 1) * 8;
}

#define H4(x)  (x)

static void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

void HELPER(gvec_fcmlas)(void *vd, void *vn, void *vm,
                         void *vfpst, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    float32 *d = vd;
    float32 *n = vn;
    float32 *m = vm;
    float_status *fpst = vfpst;
    intptr_t flip = extract32(desc, SIMD_DATA_SHIFT, 1);
    uint32_t neg_imag = extract32(desc, SIMD_DATA_SHIFT + 1, 1);
    uint32_t neg_real = flip ^ neg_imag;
    uintptr_t i;

    /* Shift boolean to the sign bit so we can xor to negate.  */
    neg_real <<= 31;
    neg_imag <<= 31;

    for (i = 0; i < opr_sz / 4; i += 2) {
        float32 e2 = n[H4(i + flip)];
        float32 e1 = m[H4(i + flip)] ^ neg_real;
        float32 e4 = e2;
        float32 e3 = m[H4(i + 1 - flip)] ^ neg_imag;

        d[H4(i)] = float32_muladd(e2, e1, d[H4(i)], 0, fpst);
        d[H4(i + 1)] = float32_muladd(e4, e3, d[H4(i + 1)], 0, fpst);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

float internal_fmaf(float x, float y, float z) {
  __asm__("fmadd %s0, %s1, %s2, %s3" : "=w"(x) : "w"(x), "w"(y), "w"(z));
  return x;
}
