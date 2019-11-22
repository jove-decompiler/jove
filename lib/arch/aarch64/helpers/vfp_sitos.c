#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

typedef uint8_t flag;

typedef uint32_t float32;

#define float32_val(x) (x)

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

#define HELPER(name) glue(helper_, name)

void float_raise(uint8_t flags, float_status *status);

float32 int32_to_float32(int32_t, float_status *status);

int32_t float32_to_int32(float32, float_status *status);

int32_t float32_to_int32_round_to_zero(float32, float_status *status);

static inline int float32_is_any_nan(float32 a)
{
    return ((float32_val(a) & ~(1 << 31)) > 0x7f800000UL);
}

#define CONV_ITOF(name, ftype, fsz, sign)                           \
ftype HELPER(name)(uint32_t x, void *fpstp)                         \
{                                                                   \
    float_status *fpst = fpstp;                                     \
    return sign##int32_to_##float##fsz((sign##int32_t)x, fpst);     \
}

#define CONV_FTOI(name, ftype, fsz, sign, round)                \
sign##int32_t HELPER(name)(ftype x, void *fpstp)                \
{                                                               \
    float_status *fpst = fpstp;                                 \
    if (float##fsz##_is_any_nan(x)) {                           \
        float_raise(float_flag_invalid, fpst);                  \
        return 0;                                               \
    }                                                           \
    return float##fsz##_to_##sign##int32##round(x, fpst);       \
}

#define FLOAT_CONVS(name, p, ftype, fsz, sign)            \
    CONV_ITOF(vfp_##name##to##p, ftype, fsz, sign)        \
    CONV_FTOI(vfp_to##name##p, ftype, fsz, sign, )        \
    CONV_FTOI(vfp_to##name##z##p, ftype, fsz, sign, _round_to_zero)

FLOAT_CONVS(si, s, float32, 32, )

