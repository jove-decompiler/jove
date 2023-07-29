#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

typedef uint16_t float16;

typedef uint32_t float32;

typedef uint64_t float64;

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

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

static inline int32_t sextract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    /* Note that this implementation relies on right shift of signed
     * integers being an arithmetic shift.
     */
    return ((int32_t)(value << (32 - length - start))) >> (32 - length);
}

# define ARM_MAX_VQ    16

typedef struct ARMVectorReg {
    uint64_t d[2 * ARM_MAX_VQ] QEMU_ALIGNED(16);
} ARMVectorReg;

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

#define SIMD_DATA_SHIFT    (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_DATA_BITS     (32 - SIMD_DATA_SHIFT)

static inline intptr_t simd_maxsz(uint32_t desc)
{
    return extract32(desc, SIMD_MAXSZ_SHIFT, SIMD_MAXSZ_BITS) * 8 + 8;
}

static inline int32_t simd_data(uint32_t desc)
{
    return sextract32(desc, SIMD_DATA_SHIFT, SIMD_DATA_BITS);
}

#define HELPER(name) glue(helper_, name)

static inline void set_float_rounding_mode(FloatRoundMode val,
                                           float_status *status)
{
    status->float_rounding_mode = val;
}

static inline void set_default_nan_mode(bool val, float_status *status)
{
    status->default_nan_mode = val;
}

float64 float16_to_float64(float16 a, bool ieee, float_status *status);

float32 float32_add(float32, float32, float_status *status);

float32 float64_to_float32(float64, float_status *status);

float64 float64_mul(float64, float64, float_status *status);

float64 float64r32_muladd(float64, float64, float64, int, float_status *status);

#define H1_4(x) (x)

#define H2(x)   (x)

#define tile_vslice_offset(byteoff) ((byteoff) * sizeof(ARMVectorReg))

static inline uint32_t f16mop_adj_pair(uint32_t pair, uint32_t pg, uint32_t neg)
{
    /*
     * The pseudocode uses a conditional negate after the conditional zero.
     * It is simpler here to unconditionally negate before conditional zero.
     */
    pair ^= neg;
    if (!(pg & 1)) {
        pair &= 0xffff0000u;
    }
    if (!(pg & 4)) {
        pair &= 0x0000ffffu;
    }
    return pair;
}

static float32 f16_dotadd(float32 sum, uint32_t e1, uint32_t e2,
                          float_status *s_std, float_status *s_odd)
{
    float64 e1r = float16_to_float64(e1 & 0xffff, true, s_std);
    float64 e1c = float16_to_float64(e1 >> 16, true, s_std);
    float64 e2r = float16_to_float64(e2 & 0xffff, true, s_std);
    float64 e2c = float16_to_float64(e2 >> 16, true, s_std);
    float64 t64;
    float32 t32;

    /*
     * The ARM pseudocode function FPDot performs both multiplies
     * and the add with a single rounding operation.  Emulate this
     * by performing the first multiply in round-to-odd, then doing
     * the second multiply as fused multiply-add, and rounding to
     * float32 all in one step.
     */
    t64 = float64_mul(e1r, e2r, s_odd);
    t64 = float64r32_muladd(e1c, e2c, t64, 0, s_std);

    /* This conversion is exact, because we've already rounded. */
    t32 = float64_to_float32(t64, s_std);

    /* The final accumulation step is not fused. */
    return float32_add(sum, t32, s_std);
}

void HELPER(sme_fmopa_h)(void *vza, void *vzn, void *vzm, void *vpn,
                         void *vpm, void *vst, uint32_t desc)
{
    intptr_t row, col, oprsz = simd_maxsz(desc);
    uint32_t neg = simd_data(desc) * 0x80008000u;
    uint16_t *pn = vpn, *pm = vpm;
    float_status fpst_odd, fpst_std;

    /*
     * Make a copy of float_status because this operation does not
     * update the cumulative fp exception status.  It also produces
     * default nans.  Make a second copy with round-to-odd -- see above.
     */
    fpst_std = *(float_status *)vst;
    set_default_nan_mode(true, &fpst_std);
    fpst_odd = fpst_std;
    set_float_rounding_mode(float_round_to_odd, &fpst_odd);

    for (row = 0; row < oprsz; ) {
        uint16_t prow = pn[H2(row >> 4)];
        do {
            void *vza_row = vza + tile_vslice_offset(row);
            uint32_t n = *(uint32_t *)(vzn + H1_4(row));

            n = f16mop_adj_pair(n, prow, neg);

            for (col = 0; col < oprsz; ) {
                uint16_t pcol = pm[H2(col >> 4)];
                do {
                    if (prow & pcol & 0b0101) {
                        uint32_t *a = vza_row + H1_4(col);
                        uint32_t m = *(uint32_t *)(vzm + H1_4(col));

                        m = f16mop_adj_pair(m, pcol, 0);
                        *a = f16_dotadd(*a, n, m, &fpst_std, &fpst_odd);

                        col += 4;
                        pcol >>= 4;
                    }
                } while (col & 15);
            }
            row += 4;
            prow >>= 4;
        } while (row & 15);
    }
}

