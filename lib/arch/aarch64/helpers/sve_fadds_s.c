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

# define QEMU_HARDFLOAT_2F32_USE_FP 0

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

typedef bool (*f32_check_fn)(union_float32 a, union_float32 b);

typedef float32 (*soft_f32_op2_fn)(float32 a, float32 b, float_status *s);

typedef float   (*hard_f32_op2_fn)(float a, float b);

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
    } else if (unlikely(_fabsf(ur.h) <= FLT_MIN)) {
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
    __builtin_trap();__builtin_unreachable();
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

static float hard_f32_add(float a, float b)
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

static float32 float32_addsub(float32 a, float32 b, float_status *s,
                              hard_f32_op2_fn hard, soft_f32_op2_fn soft)
{
    return float32_gen2(a, b, s, hard, soft,
                        f32_is_zon2, f32_addsub_post, NULL, NULL);
}

float32 QEMU_FLATTEN
float32_add(float32 a, float32 b, float_status *s)
{
    return float32_addsub(a, b, s, hard_f32_add, soft_f32_add);
}

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

#define H1_4(x) (x)

#define DO_ZPZS_FP(NAME, TYPE, H, OP) \
void HELPER(NAME)(void *vd, void *vn, void *vg, uint64_t scalar,  \
                  void *status, uint32_t desc)                    \
{                                                                 \
    intptr_t i = simd_oprsz(desc);                                \
    uint64_t *g = vg;                                             \
    TYPE mm = scalar;                                             \
    do {                                                          \
        uint64_t pg = g[(i - 1) >> 6];                            \
        do {                                                      \
            i -= sizeof(TYPE);                                    \
            if (likely((pg >> (i & 63)) & 1)) {                   \
                TYPE nn = *(TYPE *)(vn + H(i));                   \
                *(TYPE *)(vd + H(i)) = OP(nn, mm, status);        \
            }                                                     \
        } while (i & 63);                                         \
    } while (i != 0);                                             \
}

DO_ZPZS_FP(sve_fadds_s, float32, H1_4, float32_add)

