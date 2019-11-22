#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#include <stddef.h>

#include <stdint.h>

#include <stdio.h>

typedef uint8_t flag;

#define float64_val(x) (x)

typedef uint64_t float64;

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

float64 int64_to_float64_scalbn(int64_t, int, float_status *status);

int64_t float64_to_int64_scalbn(float64, int, int, float_status *status);

static inline int float64_is_any_nan(float64 a)
{
    return ((float64_val(a) & ~(1ULL << 63)) > 0x7ff0000000000000ULL);
}

#define VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype) \
float##fsz HELPER(vfp_##name##to##p)(uint##isz##_t  x, uint32_t shift, \
                                     void *fpstp) \
{ return itype##_to_##float##fsz##_scalbn(x, -shift, fpstp); }

#define VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype, ROUND, suff)   \
uint##isz##_t HELPER(vfp_to##name##p##suff)(float##fsz x, uint32_t shift, \
                                            void *fpst)                   \
{                                                                         \
    if (unlikely(float##fsz##_is_any_nan(x))) {                           \
        float_raise(float_flag_invalid, fpst);                            \
        return 0;                                                         \
    }                                                                     \
    return float##fsz##_to_##itype##_scalbn(x, ROUND, shift, fpst);       \
}

#define VFP_CONV_FIX_A64(name, p, fsz, isz, itype)               \
VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype)                     \
VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype,               \
                         get_float_rounding_mode(fpst), )

VFP_CONV_FIX_A64(sq, d, 64, 64, int64)

