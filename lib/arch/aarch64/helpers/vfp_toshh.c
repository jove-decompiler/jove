#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#include <stddef.h>

#include <stdint.h>

#include <stdio.h>

typedef uint8_t flag;

typedef uint16_t float16;

#define float16_val(x) (x)

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

static inline int get_float_rounding_mode(float_status *status)
{
    return status->float_rounding_mode;
}

void float_raise(uint8_t flags, float_status *status);

int16_t float16_to_int16_scalbn(float16, int, int, float_status *status);

static inline int float16_is_any_nan(float16 a)
{
    return ((float16_val(a) & ~0x8000) > 0x7c00);
}

uint32_t HELPER(vfp_toshh)(uint32_t x, uint32_t shift, void *fpst)
{
    if (unlikely(float16_is_any_nan(x))) {
        float_raise(float_flag_invalid, fpst);
        return 0;
    }
    return float16_to_int16_scalbn(x, get_float_rounding_mode(fpst),
                                   shift, fpst);
}

