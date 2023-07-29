#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

typedef uint16_t float16;

#define float16_val(x) (x)

typedef enum __attribute__((__packed__)) {
    float_round_nearest_even = 0,
    float_round_down         = 1,
    float_round_up           = 2,
    float_round_to_zero      = 3,
    float_round_ties_away    = 4,
    /* Not an IEEE rounding mode: round to closest odd, overflow to max */
    float_round_to_odd       = 5,
    /* Not an IEEE rounding mode: round to closest odd, overflow to inf */
    float_round_to_odd_inf   = 6,
} FloatRoundMode;

enum {
    float_flag_invalid         = 0x0001,
    float_flag_divbyzero       = 0x0002,
    float_flag_overflow        = 0x0004,
    float_flag_underflow       = 0x0008,
    float_flag_inexact         = 0x0010,
    float_flag_input_denormal  = 0x0020,
    float_flag_output_denormal = 0x0040,
    float_flag_invalid_isi     = 0x0080,  /* inf - inf */
    float_flag_invalid_imz     = 0x0100,  /* inf * 0 */
    float_flag_invalid_idi     = 0x0200,  /* inf / inf */
    float_flag_invalid_zdz     = 0x0400,  /* 0 / 0 */
    float_flag_invalid_sqrt    = 0x0800,  /* sqrt(-x) */
    float_flag_invalid_cvti    = 0x1000,  /* non-nan to integer */
    float_flag_invalid_snan    = 0x2000,  /* any operand was snan */
};

typedef enum __attribute__((__packed__)) {
    floatx80_precision_x,
    floatx80_precision_d,
    floatx80_precision_s,
} FloatX80RoundPrec;

typedef struct float_status {
    uint16_t float_exception_flags;
    FloatRoundMode float_rounding_mode;
    FloatX80RoundPrec floatx80_rounding_precision;
    bool tininess_before_rounding;
    /* should denormalised results go to zero and set the inexact flag? */
    bool flush_to_zero;
    /* should denormalised inputs go to zero and set the input_denormal flag? */
    bool flush_inputs_to_zero;
    bool default_nan_mode;
    /*
     * The flags below are not used on all specializations and may
     * constant fold away (see snan_bit_is_one()/no_signalling_nans() in
     * softfloat-specialize.inc.c)
     */
    bool snan_bit_is_one;
    bool use_first_nan;
    bool no_signaling_nans;
    /* should overflowed results subtract re_bias to its exponent? */
    bool rebias_overflow;
    /* should underflowed results add re_bias to its exponent? */
    bool rebias_underflow;
} float_status;

#define HELPER(name) glue(helper_, name)

#define dh_ctype_f16 uint32_t

static inline FloatRoundMode get_float_rounding_mode(float_status *status)
{
    return status->float_rounding_mode;
}

static inline void float_raise(uint16_t flags, float_status *status)
{
    status->float_exception_flags |= flags;
}

float16 uint16_to_float16_scalbn(uint16_t a, int, float_status *status);

uint16_t float16_to_uint16_scalbn(float16 a, FloatRoundMode,
                                  int, float_status *status);

static inline bool float16_is_any_nan(float16 a)
{
    return ((float16_val(a) & ~0x8000) > 0x7c00);
}

#define VFP_CONV_FIX_FLOAT(name, p, fsz, ftype, isz, itype)            \
ftype HELPER(vfp_##name##to##p)(uint##isz##_t  x, uint32_t shift,      \
                                     void *fpstp) \
{ return itype##_to_##float##fsz##_scalbn(x, -shift, fpstp); }

#define VFP_CONV_FIX_FLOAT_ROUND(name, p, fsz, ftype, isz, itype)      \
    ftype HELPER(vfp_##name##to##p##_round_to_nearest)(uint##isz##_t  x, \
                                                     uint32_t shift,   \
                                                     void *fpstp)      \
    {                                                                  \
        ftype ret;                                                     \
        float_status *fpst = fpstp;                                    \
        FloatRoundMode oldmode = fpst->float_rounding_mode;            \
        fpst->float_rounding_mode = float_round_nearest_even;          \
        ret = itype##_to_##float##fsz##_scalbn(x, -shift, fpstp);      \
        fpst->float_rounding_mode = oldmode;                           \
        return ret;                                                    \
    }

#define VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, ftype, isz, itype, ROUND, suff) \
uint##isz##_t HELPER(vfp_to##name##p##suff)(ftype x, uint32_t shift,      \
                                            void *fpst)                   \
{                                                                         \
    if (unlikely(float##fsz##_is_any_nan(x))) {                           \
        float_raise(float_flag_invalid, fpst);                            \
        return 0;                                                         \
    }                                                                     \
    return float##fsz##_to_##itype##_scalbn(x, ROUND, shift, fpst);       \
}

#define VFP_CONV_FIX(name, p, fsz, ftype, isz, itype)            \
VFP_CONV_FIX_FLOAT(name, p, fsz, ftype, isz, itype)              \
VFP_CONV_FIX_FLOAT_ROUND(name, p, fsz, ftype, isz, itype)        \
VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, ftype, isz, itype,        \
                         float_round_to_zero, _round_to_zero)    \
VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, ftype, isz, itype,        \
                         get_float_rounding_mode(fpst), )

VFP_CONV_FIX(uh, h, 16, dh_ctype_f16, 32, uint16)

