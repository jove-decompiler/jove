#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

typedef uint16_t float16;

typedef uint32_t float32;

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

float16 float16_min(float16, float16, float_status *status);

float32 float32_min(float32, float32, float_status *status);

#define H2(x)   (x)

#define H4(x)   (x)

#define DO_NEON_PAIRWISE(NAME, OP)                                      \
    void HELPER(NAME##s)(void *vd, void *vn, void *vm,                  \
                         void *stat, uint32_t oprsz)                    \
    {                                                                   \
        float_status *fpst = stat;                                      \
        float32 *d = vd;                                                \
        float32 *n = vn;                                                \
        float32 *m = vm;                                                \
        float32 r0, r1;                                                 \
                                                                        \
        /* Read all inputs before writing outputs in case vm == vd */   \
        r0 = float32_##OP(n[H4(0)], n[H4(1)], fpst);                    \
        r1 = float32_##OP(m[H4(0)], m[H4(1)], fpst);                    \
                                                                        \
        d[H4(0)] = r0;                                                  \
        d[H4(1)] = r1;                                                  \
    }                                                                   \
                                                                        \
    void HELPER(NAME##h)(void *vd, void *vn, void *vm,                  \
                         void *stat, uint32_t oprsz)                    \
    {                                                                   \
        float_status *fpst = stat;                                      \
        float16 *d = vd;                                                \
        float16 *n = vn;                                                \
        float16 *m = vm;                                                \
        float16 r0, r1, r2, r3;                                         \
                                                                        \
        /* Read all inputs before writing outputs in case vm == vd */   \
        r0 = float16_##OP(n[H2(0)], n[H2(1)], fpst);                    \
        r1 = float16_##OP(n[H2(2)], n[H2(3)], fpst);                    \
        r2 = float16_##OP(m[H2(0)], m[H2(1)], fpst);                    \
        r3 = float16_##OP(m[H2(2)], m[H2(3)], fpst);                    \
                                                                        \
        d[H2(0)] = r0;                                                  \
        d[H2(1)] = r1;                                                  \
        d[H2(2)] = r2;                                                  \
        d[H2(3)] = r3;                                                  \
    }

DO_NEON_PAIRWISE(neon_pmin, min)

