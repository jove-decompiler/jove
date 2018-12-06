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
    flag snan_bit_is_one;
} float_status;

#define HELPER(name) glue(helper_, name)

static inline void set_float_exception_flags(int val, float_status *status)
{
    status->float_exception_flags = val;
}

static inline int get_float_exception_flags(float_status *status)
{
    return status->float_exception_flags;
}

void float_raise(uint8_t flags, float_status *status);

float32 uint64_to_float32(uint64_t, float_status *status);

uint64_t float32_to_uint64(float32, float_status *status);

float32 float32_scalbn(float32, int, float_status *status);

static inline int float32_is_any_nan(float32 a)
{
    return ((float32_val(a) & ~(1 << 31)) > 0x7f800000UL);
}

#define VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype) \
float##fsz HELPER(vfp_##name##to##p)(uint##isz##_t  x, uint32_t shift, \
                                     void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    float##fsz tmp; \
    tmp = itype##_to_##float##fsz(x, fpst); \
    return float##fsz##_scalbn(tmp, -(int)shift, fpst); \
}

#define VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype, round) \
uint##isz##_t HELPER(vfp_to##name##p##round)(float##fsz x, \
                                             uint32_t shift, \
                                             void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    int old_exc_flags = get_float_exception_flags(fpst); \
    float##fsz tmp; \
    if (float##fsz##_is_any_nan(x)) { \
        float_raise(float_flag_invalid, fpst); \
        return 0; \
    } \
    tmp = float##fsz##_scalbn(x, shift, fpst); \
    old_exc_flags |= get_float_exception_flags(fpst) \
        & float_flag_input_denormal; \
    set_float_exception_flags(old_exc_flags, fpst); \
    return float##fsz##_to_##itype##round(tmp, fpst); \
}

#define VFP_CONV_FIX_A64(name, p, fsz, isz, itype)               \
VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype)                     \
VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype, )

VFP_CONV_FIX_A64(uq, s, 32, 64, uint64)

