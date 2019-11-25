#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#define unlikely(x)   __builtin_expect(!!(x), 0)

# define QEMU_FLATTEN __attribute__((flatten))

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

#include <assert.h>

typedef uint8_t flag;

typedef uint16_t float16;

#define float16_val(x) (x)

#define make_float16(x) (x)

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

enum {
    float_relation_less      = -1,
    float_relation_equal     =  0,
    float_relation_greater   =  1,
    float_relation_unordered =  2
};

int float16_compare(float16, float16, float_status *status);

static inline float16 float16_abs(float16 a)
{
    /* Note that abs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float16(float16_val(a) & 0x7fff);
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

#define DECOMPOSED_BINARY_POINT    (64 - 2)

#define DECOMPOSED_IMPLICIT_BIT    (1ull << DECOMPOSED_BINARY_POINT)

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

#define COMPARE(name, attr, sz)                                         \
static int attr                                                         \
name(float ## sz a, float ## sz b, bool is_quiet, float_status *s)      \
{                                                                       \
    FloatParts pa = float ## sz ## _unpack_canonical(a, s);             \
    FloatParts pb = float ## sz ## _unpack_canonical(b, s);             \
    return compare_floats(pa, pb, is_quiet, s);                         \
}

static int compare_floats(FloatParts a, FloatParts b, bool is_quiet,
                          float_status *s)
{
    if (is_nan(a.cls) || is_nan(b.cls)) {
        if (!is_quiet ||
            a.cls == float_class_snan ||
            b.cls == float_class_snan) {
            s->float_exception_flags |= float_flag_invalid;
        }
        return float_relation_unordered;
    }

    if (a.cls == float_class_zero) {
        if (b.cls == float_class_zero) {
            return float_relation_equal;
        }
        return b.sign ? float_relation_greater : float_relation_less;
    } else if (b.cls == float_class_zero) {
        return a.sign ? float_relation_less : float_relation_greater;
    }

    /* The only really important thing about infinity is its sign. If
     * both are infinities the sign marks the smallest of the two.
     */
    if (a.cls == float_class_inf) {
        if ((b.cls == float_class_inf) && (a.sign == b.sign)) {
            return float_relation_equal;
        }
        return a.sign ? float_relation_less : float_relation_greater;
    } else if (b.cls == float_class_inf) {
        return b.sign ? float_relation_greater : float_relation_less;
    }

    if (a.sign != b.sign) {
        return a.sign ? float_relation_less : float_relation_greater;
    }

    if (a.exp == b.exp) {
        if (a.frac == b.frac) {
            return float_relation_equal;
        }
        if (a.sign) {
            return a.frac > b.frac ?
                float_relation_less : float_relation_greater;
        } else {
            return a.frac > b.frac ?
                float_relation_greater : float_relation_less;
        }
    } else {
        if (a.sign) {
            return a.exp > b.exp ? float_relation_less : float_relation_greater;
        } else {
            return a.exp > b.exp ? float_relation_greater : float_relation_less;
        }
    }
}

COMPARE(soft_f16_compare, QEMU_FLATTEN, 16)

int float16_compare(float16 a, float16 b, float_status *s)
{
    return soft_f16_compare(a, b, false, s);
}

#define HELPER(name) glue(helper_, name)

#define ADVSIMD_CMPRES(test) (test) ? 0xffff : 0

uint32_t HELPER(advsimd_acge_f16)(uint32_t a, uint32_t b, void *fpstp)
{
    float_status *fpst = fpstp;
    float16 f0 = float16_abs(a);
    float16 f1 = float16_abs(b);
    int compare = float16_compare(f0, f1, fpst);
    return ADVSIMD_CMPRES(compare == float_relation_greater ||
                          compare == float_relation_equal);
}

