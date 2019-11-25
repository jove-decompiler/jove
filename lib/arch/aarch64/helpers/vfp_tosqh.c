#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

#include <limits.h>

#include <assert.h>

#define G_GNUC_NORETURN                         \
  __attribute__((__noreturn__))

#define G_STRFUNC     ((const char*) (__func__))

#define MAX(a, b)  (((a) > (b)) ? (a) : (b))

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

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

typedef uint8_t flag;

typedef uint16_t float16;

#define float16_val(x) (x)

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

static inline int get_float_rounding_mode(float_status *status)
{
    return status->float_rounding_mode;
}

static inline int get_float_exception_flags(float_status *status)
{
    return status->float_exception_flags;
}

void float_raise(uint8_t flags, float_status *status);

int64_t float16_to_int64_scalbn(float16, int, int, float_status *status);

static inline int float16_is_any_nan(float16 a)
{
    return ((float16_val(a) & ~0x8000) > 0x7c00);
}

typedef enum __attribute__ ((__packed__)) {
    float_class_unclassified,
    float_class_zero,
    float_class_normal,
    float_class_inf,
    float_class_qnan,  /* all NaNs from here */
    float_class_snan,
} FloatClass;

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

static FloatParts float16a_unpack_canonical(float16 f, float_status *s,
                                            const FloatFmt *params)
{
    return sf_canonicalize(float16_unpack_raw(f), params, s);
}

static FloatParts float16_unpack_canonical(float16 f, float_status *s)
{
    return float16a_unpack_canonical(f, s, &float16_params);
}

static FloatParts return_nan(FloatParts a, float_status *s)
{
    switch (a.cls) {
    case float_class_snan:
        s->float_exception_flags |= float_flag_invalid;
        a = parts_silence_nan(a, s);
        /* fall through */
    case float_class_qnan:
        if (s->default_nan_mode) {
            return parts_default_nan(s);
        }
        break;

    default:
        __builtin_trap();__builtin_unreachable();
    }
    return a;
}

static FloatParts round_to_int(FloatParts a, int rmode,
                               int scale, float_status *s)
{
    switch (a.cls) {
    case float_class_qnan:
    case float_class_snan:
        return return_nan(a, s);

    case float_class_zero:
    case float_class_inf:
        /* already "integral" */
        break;

    case float_class_normal:
        scale = MIN(MAX(scale, -0x10000), 0x10000);
        a.exp += scale;

        if (a.exp >= DECOMPOSED_BINARY_POINT) {
            /* already integral */
            break;
        }
        if (a.exp < 0) {
            bool one;
            /* all fractional */
            s->float_exception_flags |= float_flag_inexact;
            switch (rmode) {
            case float_round_nearest_even:
                one = a.exp == -1 && a.frac > DECOMPOSED_IMPLICIT_BIT;
                break;
            case float_round_ties_away:
                one = a.exp == -1 && a.frac >= DECOMPOSED_IMPLICIT_BIT;
                break;
            case float_round_to_zero:
                one = false;
                break;
            case float_round_up:
                one = !a.sign;
                break;
            case float_round_down:
                one = a.sign;
                break;
            case float_round_to_odd:
                one = true;
                break;
            default:
                __builtin_trap();__builtin_unreachable();
            }

            if (one) {
                a.frac = DECOMPOSED_IMPLICIT_BIT;
                a.exp = 0;
            } else {
                a.cls = float_class_zero;
            }
        } else {
            uint64_t frac_lsb = DECOMPOSED_IMPLICIT_BIT >> a.exp;
            uint64_t frac_lsbm1 = frac_lsb >> 1;
            uint64_t rnd_even_mask = (frac_lsb - 1) | frac_lsb;
            uint64_t rnd_mask = rnd_even_mask >> 1;
            uint64_t inc;

            switch (rmode) {
            case float_round_nearest_even:
                inc = ((a.frac & rnd_even_mask) != frac_lsbm1 ? frac_lsbm1 : 0);
                break;
            case float_round_ties_away:
                inc = frac_lsbm1;
                break;
            case float_round_to_zero:
                inc = 0;
                break;
            case float_round_up:
                inc = a.sign ? 0 : rnd_mask;
                break;
            case float_round_down:
                inc = a.sign ? rnd_mask : 0;
                break;
            case float_round_to_odd:
                inc = a.frac & frac_lsb ? 0 : rnd_mask;
                break;
            default:
                __builtin_trap();__builtin_unreachable();
            }

            if (a.frac & rnd_mask) {
                s->float_exception_flags |= float_flag_inexact;
                a.frac += inc;
                a.frac &= ~rnd_mask;
                if (a.frac & DECOMPOSED_OVERFLOW_BIT) {
                    a.frac >>= 1;
                    a.exp++;
                }
            }
        }
        break;
    default:
        __builtin_trap();__builtin_unreachable();
    }
    return a;
}

static int64_t round_to_int_and_pack(FloatParts in, int rmode, int scale,
                                     int64_t min, int64_t max,
                                     float_status *s)
{
    uint64_t r;
    int orig_flags = get_float_exception_flags(s);
    FloatParts p = round_to_int(in, rmode, scale, s);

    switch (p.cls) {
    case float_class_snan:
    case float_class_qnan:
        s->float_exception_flags = orig_flags | float_flag_invalid;
        return max;
    case float_class_inf:
        s->float_exception_flags = orig_flags | float_flag_invalid;
        return p.sign ? min : max;
    case float_class_zero:
        return 0;
    case float_class_normal:
        if (p.exp < DECOMPOSED_BINARY_POINT) {
            r = p.frac >> (DECOMPOSED_BINARY_POINT - p.exp);
        } else if (p.exp - DECOMPOSED_BINARY_POINT < 2) {
            r = p.frac << (p.exp - DECOMPOSED_BINARY_POINT);
        } else {
            r = UINT64_MAX;
        }
        if (p.sign) {
            if (r <= -(uint64_t) min) {
                return -r;
            } else {
                s->float_exception_flags = orig_flags | float_flag_invalid;
                return min;
            }
        } else {
            if (r <= max) {
                return r;
            } else {
                s->float_exception_flags = orig_flags | float_flag_invalid;
                return max;
            }
        }
    default:
        __builtin_trap();__builtin_unreachable();
    }
}

int64_t float16_to_int64_scalbn(float16 a, int rmode, int scale,
                                float_status *s)
{
    return round_to_int_and_pack(float16_unpack_canonical(a, s),
                                 rmode, scale, INT64_MIN, INT64_MAX, s);
}

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(vfp_tosqh)(uint32_t x, uint32_t shift, void *fpst)
{
    if (unlikely(float16_is_any_nan(x))) {
        float_raise(float_flag_invalid, fpst);
        return 0;
    }
    return float16_to_int64_scalbn(x, get_float_rounding_mode(fpst),
                                   shift, fpst);
}

