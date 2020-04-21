#define TARGET_I386 1

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

#define float64_val(x) (x)

#define make_float32(x) (x)

#define make_float64(x) (x)

typedef uint64_t float64;

typedef struct {
    uint64_t low;
    uint16_t high;
} floatx80;

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

float32 float32_add(float32, float32, float_status *status);

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

float64 float64_add(float64, float64, float_status *status);

static inline int float64_is_infinity(float64 a)
{
    return (float64_val(a) & 0x7fffffffffffffffLL ) == 0x7ff0000000000000LL;
}

static inline int float64_is_neg(float64 a)
{
    return float64_val(a) >> 63;
}

static inline int float64_is_zero(float64 a)
{
    return (float64_val(a) & 0x7fffffffffffffffLL) == 0;
}

static inline int float64_is_zero_or_denormal(float64 a)
{
    return (float64_val(a) & 0x7ff0000000000000LL) == 0;
}

static inline bool float64_is_normal(float64 a)
{
    return (((float64_val(a) >> 52) + 1) & 0x7ff) >= 2;
}

static inline bool float64_is_denormal(float64 a)
{
    return float64_is_zero_or_denormal(a) && !float64_is_zero(a);
}

static inline bool float64_is_zero_or_normal(float64 a)
{
    return float64_is_normal(a) || float64_is_zero(a);
}

#define float64_zero make_float64(0)

static inline float64 float64_set_sign(float64 a, int sign)
{
    return make_float64((float64_val(a) & 0x7fffffffffffffffULL)
                        | ((int64_t)sign << 63));
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

GEN_INPUT_FLUSH__NOCHECK(float64_input_flush__nocheck, float64)

#define GEN_INPUT_FLUSH2(name, soft_t)                                  \
    static inline void name(soft_t *a, soft_t *b, float_status *s)      \
    {                                                                   \
        if (likely(!s->flush_inputs_to_zero)) {                         \
            return;                                                     \
        }                                                               \
        soft_t ## _input_flush__nocheck(a, s);                          \
        soft_t ## _input_flush__nocheck(b, s);                          \
    }

GEN_INPUT_FLUSH2(float32_input_flush2, float32)

GEN_INPUT_FLUSH2(float64_input_flush2, float64)

# define QEMU_HARDFLOAT_2F32_USE_FP 0

# define QEMU_HARDFLOAT_2F64_USE_FP 0

# define QEMU_HARDFLOAT_USE_ISINF   0

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

typedef union {
    float64 s;
    double h;
} union_float64;

typedef bool (*f32_check_fn)(union_float32 a, union_float32 b);

typedef bool (*f64_check_fn)(union_float64 a, union_float64 b);

typedef float32 (*soft_f32_op2_fn)(float32 a, float32 b, float_status *s);

typedef float64 (*soft_f64_op2_fn)(float64 a, float64 b, float_status *s);

typedef float   (*hard_f32_op2_fn)(float a, float b);

typedef double  (*hard_f64_op2_fn)(double a, double b);

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

static inline bool f64_is_zon2(union_float64 a, union_float64 b)
{
    if (QEMU_HARDFLOAT_2F64_USE_FP) {
        return (fpclassify(a.h) == FP_NORMAL || fpclassify(a.h) == FP_ZERO) &&
               (fpclassify(b.h) == FP_NORMAL || fpclassify(b.h) == FP_ZERO);
    }
    return float64_is_zero_or_normal(a.s) &&
           float64_is_zero_or_normal(b.s);
}

static inline bool f32_is_inf(union_float32 a)
{
    if (QEMU_HARDFLOAT_USE_ISINF) {
        return isinf(a.h);
    }
    return float32_is_infinity(a.s);
}

static inline bool f64_is_inf(union_float64 a)
{
    if (QEMU_HARDFLOAT_USE_ISINF) {
        return isinf(a.h);
    }
    return float64_is_infinity(a.s);
}

static inline float32
float32_gen2(float32 xa, float32 xb, float_status *s,
             hard_f32_op2_fn hard, soft_f32_op2_fn soft,
             f32_check_fn pre, f32_check_fn post,
             f32_check_fn fast_test, soft_f32_op2_fn fast_op)
{
    union_float32 ua, ub, ur;

    ua.s = xa;
    ub.s = xb;

    if (unlikely(!can_use_fpu(s))) {
        goto soft;
    }

    float32_input_flush2(&ua.s, &ub.s, s);
    if (unlikely(!pre(ua, ub))) {
        goto soft;
    }
    if (fast_test && fast_test(ua, ub)) {
        return fast_op(ua.s, ub.s, s);
    }

    ur.h = hard(ua.h, ub.h);
    if (unlikely(f32_is_inf(ur))) {
        s->float_exception_flags |= float_flag_overflow;
    } else if (unlikely(fabsf(ur.h) <= FLT_MIN)) {
        if (post == NULL || post(ua, ub)) {
            goto soft;
        }
    }
    return ur.s;

 soft:
    return soft(ua.s, ub.s, s);
}

static inline float64
float64_gen2(float64 xa, float64 xb, float_status *s,
             hard_f64_op2_fn hard, soft_f64_op2_fn soft,
             f64_check_fn pre, f64_check_fn post,
             f64_check_fn fast_test, soft_f64_op2_fn fast_op)
{
    union_float64 ua, ub, ur;

    ua.s = xa;
    ub.s = xb;

    if (unlikely(!can_use_fpu(s))) {
        goto soft;
    }

    float64_input_flush2(&ua.s, &ub.s, s);
    if (unlikely(!pre(ua, ub))) {
        goto soft;
    }
    if (fast_test && fast_test(ua, ub)) {
        return fast_op(ua.s, ub.s, s);
    }

    ur.h = hard(ua.h, ub.h);
    if (unlikely(f64_is_inf(ur))) {
        s->float_exception_flags |= float_flag_overflow;
    } else if (unlikely(fabs(ur.h) <= DBL_MIN)) {
        if (post == NULL || post(ua, ub)) {
            goto soft;
        }
    }
    return ur.s;

 soft:
    return soft(ua.s, ub.s, s);
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

static const FloatFmt float64_params = {
    FLOAT_PARAMS(11, 52)
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

static inline FloatParts float64_unpack_raw(float64 f)
{
    return unpack_raw(float64_params, f);
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

static inline float64 float64_pack_raw(FloatParts p)
{
    return make_float64(pack_raw(float64_params, p));
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
    g_assert_not_reached();
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

static int pickNaN(FloatClass a_cls, FloatClass b_cls,
                   flag aIsLargerSignificand)
{
#if defined(TARGET_ARM) || defined(TARGET_MIPS) || defined(TARGET_HPPA)
    /* ARM mandated NaN propagation rules (see FPProcessNaNs()), take
     * the first of:
     *  1. A if it is signaling
     *  2. B if it is signaling
     *  3. A (quiet)
     *  4. B (quiet)
     * A signaling NaN is always quietened before returning it.
     */
    /* According to MIPS specifications, if one of the two operands is
     * a sNaN, a new qNaN has to be generated. This is done in
     * floatXX_silence_nan(). For qNaN inputs the specifications
     * says: "When possible, this QNaN result is one of the operand QNaN
     * values." In practice it seems that most implementations choose
     * the first operand if both operands are qNaN. In short this gives
     * the following rules:
     *  1. A if it is signaling
     *  2. B if it is signaling
     *  3. A (quiet)
     *  4. B (quiet)
     * A signaling NaN is always silenced before returning it.
     */
    if (is_snan(a_cls)) {
        return 0;
    } else if (is_snan(b_cls)) {
        return 1;
    } else if (is_qnan(a_cls)) {
        return 0;
    } else {
        return 1;
    }
#elif defined(TARGET_PPC) || defined(TARGET_XTENSA) || defined(TARGET_M68K)
    /* PowerPC propagation rules:
     *  1. A if it sNaN or qNaN
     *  2. B if it sNaN or qNaN
     * A signaling NaN is always silenced before returning it.
     */
    /* M68000 FAMILY PROGRAMMER'S REFERENCE MANUAL
     * 3.4 FLOATING-POINT INSTRUCTION DETAILS
     * If either operand, but not both operands, of an operation is a
     * nonsignaling NaN, then that NaN is returned as the result. If both
     * operands are nonsignaling NaNs, then the destination operand
     * nonsignaling NaN is returned as the result.
     * If either operand to an operation is a signaling NaN (SNaN), then the
     * SNaN bit is set in the FPSR EXC byte. If the SNaN exception enable bit
     * is set in the FPCR ENABLE byte, then the exception is taken and the
     * destination is not modified. If the SNaN exception enable bit is not
     * set, setting the SNaN bit in the operand to a one converts the SNaN to
     * a nonsignaling NaN. The operation then continues as described in the
     * preceding paragraph for nonsignaling NaNs.
     */
    if (is_nan(a_cls)) {
        return 0;
    } else {
        return 1;
    }
#else
    /* This implements x87 NaN propagation rules:
     * SNaN + QNaN => return the QNaN
     * two SNaNs => return the one with the larger significand, silenced
     * two QNaNs => return the one with the larger significand
     * SNaN and a non-NaN => return the SNaN, silenced
     * QNaN and a non-NaN => return the QNaN
     *
     * If we get down to comparing significands and they are the same,
     * return the NaN with the positive sign bit (if any).
     */
    if (is_snan(a_cls)) {
        if (is_snan(b_cls)) {
            return aIsLargerSignificand ? 0 : 1;
        }
        return is_qnan(b_cls) ? 1 : 0;
    } else if (is_qnan(a_cls)) {
        if (is_snan(b_cls) || !is_qnan(b_cls)) {
            return 0;
        } else {
            return aIsLargerSignificand ? 0 : 1;
        }
    } else {
        return 1;
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
            g_assert_not_reached();
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
        g_assert_not_reached();
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

static FloatParts float64_unpack_canonical(float64 f, float_status *s)
{
    return sf_canonicalize(float64_unpack_raw(f), &float64_params, s);
}

static float64 float64_round_pack_canonical(FloatParts p, float_status *s)
{
    return float64_pack_raw(round_canonical(p, s, &float64_params));
}

static FloatParts pick_nan(FloatParts a, FloatParts b, float_status *s)
{
    if (is_snan(a.cls) || is_snan(b.cls)) {
        s->float_exception_flags |= float_flag_invalid;
    }

    if (s->default_nan_mode) {
        return parts_default_nan(s);
    } else {
        if (pickNaN(a.cls, b.cls,
                    a.frac > b.frac ||
                    (a.frac == b.frac && a.sign < b.sign))) {
            a = b;
        }
        if (is_snan(a.cls)) {
            return parts_silence_nan(a, s);
        }
    }
    return a;
}

static FloatParts addsub_floats(FloatParts a, FloatParts b, bool subtract,
                                float_status *s)
{
    bool a_sign = a.sign;
    bool b_sign = b.sign ^ subtract;

    if (a_sign != b_sign) {
        /* Subtraction */

        if (a.cls == float_class_normal && b.cls == float_class_normal) {
            if (a.exp > b.exp || (a.exp == b.exp && a.frac >= b.frac)) {
                shift64RightJamming(b.frac, a.exp - b.exp, &b.frac);
                a.frac = a.frac - b.frac;
            } else {
                shift64RightJamming(a.frac, b.exp - a.exp, &a.frac);
                a.frac = b.frac - a.frac;
                a.exp = b.exp;
                a_sign ^= 1;
            }

            if (a.frac == 0) {
                a.cls = float_class_zero;
                a.sign = s->float_rounding_mode == float_round_down;
            } else {
                int shift = clz64(a.frac) - 1;
                a.frac = a.frac << shift;
                a.exp = a.exp - shift;
                a.sign = a_sign;
            }
            return a;
        }
        if (is_nan(a.cls) || is_nan(b.cls)) {
            return pick_nan(a, b, s);
        }
        if (a.cls == float_class_inf) {
            if (b.cls == float_class_inf) {
                float_raise(float_flag_invalid, s);
                return parts_default_nan(s);
            }
            return a;
        }
        if (a.cls == float_class_zero && b.cls == float_class_zero) {
            a.sign = s->float_rounding_mode == float_round_down;
            return a;
        }
        if (a.cls == float_class_zero || b.cls == float_class_inf) {
            b.sign = a_sign ^ 1;
            return b;
        }
        if (b.cls == float_class_zero) {
            return a;
        }
    } else {
        /* Addition */
        if (a.cls == float_class_normal && b.cls == float_class_normal) {
            if (a.exp > b.exp) {
                shift64RightJamming(b.frac, a.exp - b.exp, &b.frac);
            } else if (a.exp < b.exp) {
                shift64RightJamming(a.frac, b.exp - a.exp, &a.frac);
                a.exp = b.exp;
            }
            a.frac += b.frac;
            if (a.frac & DECOMPOSED_OVERFLOW_BIT) {
                shift64RightJamming(a.frac, 1, &a.frac);
                a.exp += 1;
            }
            return a;
        }
        if (is_nan(a.cls) || is_nan(b.cls)) {
            return pick_nan(a, b, s);
        }
        if (a.cls == float_class_inf || b.cls == float_class_zero) {
            return a;
        }
        if (b.cls == float_class_inf || a.cls == float_class_zero) {
            b.sign = b_sign;
            return b;
        }
    }
    g_assert_not_reached();
}

static float32 QEMU_SOFTFLOAT_ATTR
soft_f32_addsub(float32 a, float32 b, bool subtract, float_status *status)
{
    FloatParts pa = float32_unpack_canonical(a, status);
    FloatParts pb = float32_unpack_canonical(b, status);
    FloatParts pr = addsub_floats(pa, pb, subtract, status);

    return float32_round_pack_canonical(pr, status);
}

static inline float32 soft_f32_add(float32 a, float32 b, float_status *status)
{
    return soft_f32_addsub(a, b, false, status);
}

static float64 QEMU_SOFTFLOAT_ATTR
soft_f64_addsub(float64 a, float64 b, bool subtract, float_status *status)
{
    FloatParts pa = float64_unpack_canonical(a, status);
    FloatParts pb = float64_unpack_canonical(b, status);
    FloatParts pr = addsub_floats(pa, pb, subtract, status);

    return float64_round_pack_canonical(pr, status);
}

static inline float64 soft_f64_add(float64 a, float64 b, float_status *status)
{
    return soft_f64_addsub(a, b, false, status);
}

static float hard_f32_add(float a, float b)
{
    return a + b;
}

static double hard_f64_add(double a, double b)
{
    return a + b;
}

static bool f32_addsub_post(union_float32 a, union_float32 b)
{
    if (QEMU_HARDFLOAT_2F32_USE_FP) {
        return !(fpclassify(a.h) == FP_ZERO && fpclassify(b.h) == FP_ZERO);
    }
    return !(float32_is_zero(a.s) && float32_is_zero(b.s));
}

static bool f64_addsub_post(union_float64 a, union_float64 b)
{
    if (QEMU_HARDFLOAT_2F64_USE_FP) {
        return !(fpclassify(a.h) == FP_ZERO && fpclassify(b.h) == FP_ZERO);
    } else {
        return !(float64_is_zero(a.s) && float64_is_zero(b.s));
    }
}

static float32 float32_addsub(float32 a, float32 b, float_status *s,
                              hard_f32_op2_fn hard, soft_f32_op2_fn soft)
{
    return float32_gen2(a, b, s, hard, soft,
                        f32_is_zon2, f32_addsub_post, NULL, NULL);
}

static float64 float64_addsub(float64 a, float64 b, float_status *s,
                              hard_f64_op2_fn hard, soft_f64_op2_fn soft)
{
    return float64_gen2(a, b, s, hard, soft,
                        f64_is_zon2, f64_addsub_post, NULL, NULL);
}

float32 QEMU_FLATTEN
float32_add(float32 a, float32 b, float_status *s)
{
    return float32_addsub(a, b, s, hard_f32_add, soft_f32_add);
}

float64 QEMU_FLATTEN
float64_add(float64 a, float64 b, float_status *s)
{
    return float64_addsub(a, b, s, hard_f64_add, soft_f64_add);
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

#define HV_SINT_COUNT                         16

#define HV_X64_MSR_CRASH_P0                     0x40000100

#define HV_X64_MSR_CRASH_P4                     0x40000104

#define HV_CRASH_PARAMS    (HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 + 1)

#define HV_STIMER_COUNT                       4

typedef uint32_t target_ulong;

#define MCE_BANKS_DEF   10

#define MSR_MTRRcap_VCNT                8

#define MSR_P6_EVNTSEL0                 0x186

#define MSR_IA32_PERF_STATUS            0x198

#define MAX_RTIT_ADDRS                  8

typedef enum FeatureWord {
    FEAT_1_EDX,         /* CPUID[1].EDX */
    FEAT_1_ECX,         /* CPUID[1].ECX */
    FEAT_7_0_EBX,       /* CPUID[EAX=7,ECX=0].EBX */
    FEAT_7_0_ECX,       /* CPUID[EAX=7,ECX=0].ECX */
    FEAT_7_0_EDX,       /* CPUID[EAX=7,ECX=0].EDX */
    FEAT_7_1_EAX,       /* CPUID[EAX=7,ECX=1].EAX */
    FEAT_8000_0001_EDX, /* CPUID[8000_0001].EDX */
    FEAT_8000_0001_ECX, /* CPUID[8000_0001].ECX */
    FEAT_8000_0007_EDX, /* CPUID[8000_0007].EDX */
    FEAT_8000_0008_EBX, /* CPUID[8000_0008].EBX */
    FEAT_C000_0001_EDX, /* CPUID[C000_0001].EDX */
    FEAT_KVM,           /* CPUID[4000_0001].EAX (KVM_CPUID_FEATURES) */
    FEAT_KVM_HINTS,     /* CPUID[4000_0001].EDX */
    FEAT_HYPERV_EAX,    /* CPUID[4000_0003].EAX */
    FEAT_HYPERV_EBX,    /* CPUID[4000_0003].EBX */
    FEAT_HYPERV_EDX,    /* CPUID[4000_0003].EDX */
    FEAT_HV_RECOMM_EAX, /* CPUID[4000_0004].EAX */
    FEAT_HV_NESTED_EAX, /* CPUID[4000_000A].EAX */
    FEAT_SVM,           /* CPUID[8000_000A].EDX */
    FEAT_XSAVE,         /* CPUID[EAX=0xd,ECX=1].EAX */
    FEAT_6_EAX,         /* CPUID[6].EAX */
    FEAT_XSAVE_COMP_LO, /* CPUID[EAX=0xd,ECX=0].EAX */
    FEAT_XSAVE_COMP_HI, /* CPUID[EAX=0xd,ECX=0].EDX */
    FEAT_ARCH_CAPABILITIES,
    FEAT_CORE_CAPABILITY,
    FEAT_VMX_PROCBASED_CTLS,
    FEAT_VMX_SECONDARY_CTLS,
    FEAT_VMX_PINBASED_CTLS,
    FEAT_VMX_EXIT_CTLS,
    FEAT_VMX_ENTRY_CTLS,
    FEAT_VMX_MISC,
    FEAT_VMX_EPT_VPID_CAPS,
    FEAT_VMX_BASIC,
    FEAT_VMX_VMFUNC,
    FEATURE_WORDS,
} FeatureWord;

typedef uint64_t FeatureWordArray[FEATURE_WORDS];

#define MMREG_UNION(n, bits)        \
    union n {                       \
        uint8_t  _b_##n[(bits)/8];  \
        uint16_t _w_##n[(bits)/16]; \
        uint32_t _l_##n[(bits)/32]; \
        uint64_t _q_##n[(bits)/64]; \
        float32  _s_##n[(bits)/32]; \
        float64  _d_##n[(bits)/64]; \
    }

typedef struct SegmentCache {
    uint32_t selector;
    target_ulong base;
    uint32_t limit;
    uint32_t flags;
} SegmentCache;

typedef union {
    uint8_t _b[16];
    uint16_t _w[8];
    uint32_t _l[4];
    uint64_t _q[2];
} XMMReg;

typedef union {
    uint8_t _b[32];
    uint16_t _w[16];
    uint32_t _l[8];
    uint64_t _q[4];
} YMMReg;

typedef MMREG_UNION(ZMMReg, 512) ZMMReg;

typedef MMREG_UNION(MMXReg, 64)  MMXReg;

typedef struct BNDReg {
    uint64_t lb;
    uint64_t ub;
} BNDReg;

#define ZMM_S(n) _s_ZMMReg[n]

#define ZMM_D(n) _d_ZMMReg[n]

typedef struct BNDCSReg {
    uint64_t cfgu;
    uint64_t sts;
} BNDCSReg;

typedef union {
    floatx80 d __attribute__((aligned(16)));
    MMXReg mmx;
} FPReg;

#define CPU_NB_REGS32 8

#define CPU_NB_REGS CPU_NB_REGS32

#define MAX_FIXED_COUNTERS 3

#define MAX_GP_COUNTERS    (MSR_IA32_PERF_STATUS - MSR_P6_EVNTSEL0)

#define NB_OPMASK_REGS 8

typedef struct {
    uint64_t base;
    uint64_t mask;
} MTRRVar;

typedef enum TPRAccess {
    TPR_ACCESS_READ,
    TPR_ACCESS_WRITE,
} TPRAccess;

enum CacheType {
    DATA_CACHE,
    INSTRUCTION_CACHE,
    UNIFIED_CACHE
};

typedef struct CPUCacheInfo {
    enum CacheType type;
    uint8_t level;
    /* Size in bytes */
    uint32_t size;
    /* Line size, in bytes */
    uint16_t line_size;
    /*
     * Associativity.
     * Note: representation of fully-associative caches is not implemented
     */
    uint8_t associativity;
    /* Physical line partitions. CPUID[0x8000001D].EBX, CPUID[4].EBX */
    uint8_t partitions;
    /* Number of sets. CPUID[0x8000001D].ECX, CPUID[4].ECX */
    uint32_t sets;
    /*
     * Lines per tag.
     * AMD-specific: CPUID[0x80000005], CPUID[0x80000006].
     * (Is this synonym to @partitions?)
     */
    uint8_t lines_per_tag;

    /* Self-initializing cache */
    bool self_init;
    /*
     * WBINVD/INVD is not guaranteed to act upon lower level caches of
     * non-originating threads sharing this cache.
     * CPUID[4].EDX[bit 0], CPUID[0x8000001D].EDX[bit 0]
     */
    bool no_invd_sharing;
    /*
     * Cache is inclusive of lower cache levels.
     * CPUID[4].EDX[bit 1], CPUID[0x8000001D].EDX[bit 1].
     */
    bool inclusive;
    /*
     * A complex function is used to index the cache, potentially using all
     * address bits.  CPUID[4].EDX[bit 2].
     */
    bool complex_indexing;
} CPUCacheInfo;

typedef struct CPUCaches {
        CPUCacheInfo *l1d_cache;
        CPUCacheInfo *l1i_cache;
        CPUCacheInfo *l2_cache;
        CPUCacheInfo *l3_cache;
} CPUCaches;

typedef struct CPUX86State {
    /* standard registers */
    target_ulong regs[CPU_NB_REGS];
    target_ulong eip;
    target_ulong eflags; /* eflags register. During CPU emulation, CC
                        flags and DF are set to zero because they are
                        stored elsewhere */

    /* emulator internal eflags handling */
    target_ulong cc_dst;
    target_ulong cc_src;
    target_ulong cc_src2;
    uint32_t cc_op;
    int32_t df; /* D flag : 1 if D = 0, -1 if D = 1 */
    uint32_t hflags; /* TB flags, see HF_xxx constants. These flags
                        are known at translation time. */
    uint32_t hflags2; /* various other flags, see HF2_xxx constants. */

    /* segments */
    SegmentCache segs[6]; /* selector values */
    SegmentCache ldt;
    SegmentCache tr;
    SegmentCache gdt; /* only base and limit are used */
    SegmentCache idt; /* only base and limit are used */

    target_ulong cr[5]; /* NOTE: cr1 is unused */
    int32_t a20_mask;

    BNDReg bnd_regs[4];
    BNDCSReg bndcs_regs;
    uint64_t msr_bndcfgs;
    uint64_t efer;

    /* Beginning of state preserved by INIT (dummy marker).  */
    struct {} start_init_save;

    /* FPU state */
    unsigned int fpstt; /* top of stack index */
    uint16_t fpus;
    uint16_t fpuc;
    uint8_t fptags[8];   /* 0 = valid, 1 = empty */
    FPReg fpregs[8];
    /* KVM-only so far */
    uint16_t fpop;
    uint64_t fpip;
    uint64_t fpdp;

    /* emulator internal variables */
    float_status fp_status;
    floatx80 ft0;

    float_status mmx_status; /* for 3DNow! float ops */
    float_status sse_status;
    uint32_t mxcsr;
    ZMMReg xmm_regs[CPU_NB_REGS == 8 ? 8 : 32];
    ZMMReg xmm_t0;
    MMXReg mmx_t0;

    XMMReg ymmh_regs[CPU_NB_REGS];

    uint64_t opmask_regs[NB_OPMASK_REGS];
    YMMReg zmmh_regs[CPU_NB_REGS];
    ZMMReg hi16_zmm_regs[CPU_NB_REGS];

    /* sysenter registers */
    uint32_t sysenter_cs;
    target_ulong sysenter_esp;
    target_ulong sysenter_eip;
    uint64_t star;

    uint64_t vm_hsave;

#ifdef TARGET_X86_64
    target_ulong lstar;
    target_ulong cstar;
    target_ulong fmask;
    target_ulong kernelgsbase;
#endif

    uint64_t tsc;
    uint64_t tsc_adjust;
    uint64_t tsc_deadline;
    uint64_t tsc_aux;

    uint64_t xcr0;

    uint64_t mcg_status;
    uint64_t msr_ia32_misc_enable;
    uint64_t msr_ia32_feature_control;

    uint64_t msr_fixed_ctr_ctrl;
    uint64_t msr_global_ctrl;
    uint64_t msr_global_status;
    uint64_t msr_global_ovf_ctrl;
    uint64_t msr_fixed_counters[MAX_FIXED_COUNTERS];
    uint64_t msr_gp_counters[MAX_GP_COUNTERS];
    uint64_t msr_gp_evtsel[MAX_GP_COUNTERS];

    uint64_t pat;
    uint32_t smbase;
    uint64_t msr_smi_count;

    uint32_t pkru;
    uint32_t tsx_ctrl;

    uint64_t spec_ctrl;
    uint64_t virt_ssbd;

    /* End of state preserved by INIT (dummy marker).  */
    struct {} end_init_save;

    uint64_t system_time_msr;
    uint64_t wall_clock_msr;
    uint64_t steal_time_msr;
    uint64_t async_pf_en_msr;
    uint64_t pv_eoi_en_msr;
    uint64_t poll_control_msr;

    /* Partition-wide HV MSRs, will be updated only on the first vcpu */
    uint64_t msr_hv_hypercall;
    uint64_t msr_hv_guest_os_id;
    uint64_t msr_hv_tsc;

    /* Per-VCPU HV MSRs */
    uint64_t msr_hv_vapic;
    uint64_t msr_hv_crash_params[HV_CRASH_PARAMS];
    uint64_t msr_hv_runtime;
    uint64_t msr_hv_synic_control;
    uint64_t msr_hv_synic_evt_page;
    uint64_t msr_hv_synic_msg_page;
    uint64_t msr_hv_synic_sint[HV_SINT_COUNT];
    uint64_t msr_hv_stimer_config[HV_STIMER_COUNT];
    uint64_t msr_hv_stimer_count[HV_STIMER_COUNT];
    uint64_t msr_hv_reenlightenment_control;
    uint64_t msr_hv_tsc_emulation_control;
    uint64_t msr_hv_tsc_emulation_status;

    uint64_t msr_rtit_ctrl;
    uint64_t msr_rtit_status;
    uint64_t msr_rtit_output_base;
    uint64_t msr_rtit_output_mask;
    uint64_t msr_rtit_cr3_match;
    uint64_t msr_rtit_addrs[MAX_RTIT_ADDRS];

    /* exception/interrupt handling */
    int error_code;
    int exception_is_int;
    target_ulong exception_next_eip;
    target_ulong dr[8]; /* debug registers; note dr4 and dr5 are unused */
    union {
        struct CPUBreakpoint *cpu_breakpoint[4];
        struct CPUWatchpoint *cpu_watchpoint[4];
    }; /* break/watchpoints for dr[0..3] */
    int old_exception;  /* exception in flight */

    uint64_t vm_vmcb;
    uint64_t tsc_offset;
    uint64_t intercept;
    uint16_t intercept_cr_read;
    uint16_t intercept_cr_write;
    uint16_t intercept_dr_read;
    uint16_t intercept_dr_write;
    uint32_t intercept_exceptions;
    uint64_t nested_cr3;
    uint32_t nested_pg_mode;
    uint8_t v_tpr;

    /* KVM states, automatically cleared on reset */
    uint8_t nmi_injected;
    uint8_t nmi_pending;

    uintptr_t retaddr;

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    /* Fields after this point are preserved across CPU reset. */

    /* processor features (e.g. for CPUID insn) */
    /* Minimum cpuid leaf 7 value */
    uint32_t cpuid_level_func7;
    /* Actual cpuid leaf 7 value */
    uint32_t cpuid_min_level_func7;
    /* Minimum level/xlevel/xlevel2, based on CPU model + features */
    uint32_t cpuid_min_level, cpuid_min_xlevel, cpuid_min_xlevel2;
    /* Maximum level/xlevel/xlevel2 value for auto-assignment: */
    uint32_t cpuid_max_level, cpuid_max_xlevel, cpuid_max_xlevel2;
    /* Actual level/xlevel/xlevel2 value: */
    uint32_t cpuid_level, cpuid_xlevel, cpuid_xlevel2;
    uint32_t cpuid_vendor1;
    uint32_t cpuid_vendor2;
    uint32_t cpuid_vendor3;
    uint32_t cpuid_version;
    FeatureWordArray features;
    /* Features that were explicitly enabled/disabled */
    FeatureWordArray user_features;
    uint32_t cpuid_model[12];
    /* Cache information for CPUID.  When legacy-cache=on, the cache data
     * on each CPUID leaf will be different, because we keep compatibility
     * with old QEMU versions.
     */
    CPUCaches cache_info_cpuid2, cache_info_cpuid4, cache_info_amd;

    /* MTRRs */
    uint64_t mtrr_fixed[11];
    uint64_t mtrr_deftype;
    MTRRVar mtrr_var[MSR_MTRRcap_VCNT];

    /* For KVM */
    uint32_t mp_state;
    int32_t exception_nr;
    int32_t interrupt_injected;
    uint8_t soft_interrupt;
    uint8_t exception_pending;
    uint8_t exception_injected;
    uint8_t has_error_code;
    uint8_t exception_has_payload;
    uint64_t exception_payload;
    uint32_t ins_len;
    uint32_t sipi_vector;
    bool tsc_valid;
    int64_t tsc_khz;
    int64_t user_tsc_khz; /* for sanity check only */
#if defined(CONFIG_KVM) || defined(CONFIG_HVF)
    void *xsave_buf;
#endif
#if defined(CONFIG_KVM)
    struct kvm_nested_state *nested_state;
#endif
#if defined(CONFIG_HVF)
    HVFX86EmulatorState *hvf_emul;
#endif

    uint64_t mcg_cap;
    uint64_t mcg_ctl;
    uint64_t mcg_ext_ctl;
    uint64_t mce_banks[MCE_BANKS_DEF*4];
    uint64_t xstate_bv;

    /* vmstate */
    uint16_t fpus_vmstate;
    uint16_t fptag_vmstate;
    uint16_t fpregs_format_vmstate;

    uint64_t xss;
    uint32_t umwait;

    TPRAccess tpr_access_type;

    unsigned nr_dies;
} CPUX86State;

#define Reg ZMMReg

#define SSE_HELPER_S(name, F)                                           \
    void helper_ ## name ## ps(CPUX86State *env, Reg *d, Reg *s)        \
    {                                                                   \
        d->ZMM_S(0) = F(32, d->ZMM_S(0), s->ZMM_S(0));                  \
        d->ZMM_S(1) = F(32, d->ZMM_S(1), s->ZMM_S(1));                  \
        d->ZMM_S(2) = F(32, d->ZMM_S(2), s->ZMM_S(2));                  \
        d->ZMM_S(3) = F(32, d->ZMM_S(3), s->ZMM_S(3));                  \
    }                                                                   \
                                                                        \
    void helper_ ## name ## ss(CPUX86State *env, Reg *d, Reg *s)        \
    {                                                                   \
        d->ZMM_S(0) = F(32, d->ZMM_S(0), s->ZMM_S(0));                  \
    }                                                                   \
                                                                        \
    void helper_ ## name ## pd(CPUX86State *env, Reg *d, Reg *s)        \
    {                                                                   \
        d->ZMM_D(0) = F(64, d->ZMM_D(0), s->ZMM_D(0));                  \
        d->ZMM_D(1) = F(64, d->ZMM_D(1), s->ZMM_D(1));                  \
    }                                                                   \
                                                                        \
    void helper_ ## name ## sd(CPUX86State *env, Reg *d, Reg *s)        \
    {                                                                   \
        d->ZMM_D(0) = F(64, d->ZMM_D(0), s->ZMM_D(0));                  \
    }

#define FPU_ADD(size, a, b) float ## size ## _add(a, b, &env->sse_status)

SSE_HELPER_S(add, FPU_ADD)

