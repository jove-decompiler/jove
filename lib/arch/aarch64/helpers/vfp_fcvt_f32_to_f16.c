#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

typedef uint8_t flag;

typedef uint16_t float16;

typedef uint32_t float32;

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

static inline void set_flush_to_zero(flag val, float_status *status)
{
    status->flush_to_zero = val;
}

static inline flag get_flush_to_zero(float_status *status)
{
    return status->flush_to_zero;
}

float16 float32_to_float16(float32, bool ieee, float_status *status);

uint32_t HELPER(vfp_fcvt_f32_to_f16)(float32 a, void *fpstp, uint32_t ahp_mode)
{
    /* Squash FZ16 to 0 for the duration of conversion.  In this case,
     * it would affect flushing output denormals.
     */
    float_status *fpst = fpstp;
    flag save = get_flush_to_zero(fpst);
    set_flush_to_zero(false, fpst);
    float16 r = float32_to_float16(a, !ahp_mode, fpst);
    set_flush_to_zero(save, fpst);
    return r;
}

