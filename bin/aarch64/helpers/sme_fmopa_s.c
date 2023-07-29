#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

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

static inline void set_default_nan_mode(bool val, float_status *status)
{
    status->default_nan_mode = val;
}

float32 float32_muladd(float32, float32, float32, int, float_status *status);

#define H1_4(x) (x)

#define H2(x)   (x)

#define tile_vslice_offset(byteoff) ((byteoff) * sizeof(ARMVectorReg))

void HELPER(sme_fmopa_s)(void *vza, void *vzn, void *vzm, void *vpn,
                         void *vpm, void *vst, uint32_t desc)
{
    intptr_t row, col, oprsz = simd_maxsz(desc);
    uint32_t neg = simd_data(desc) << 31;
    uint16_t *pn = vpn, *pm = vpm;
    float_status fpst;

    /*
     * Make a copy of float_status because this operation does not
     * update the cumulative fp exception status.  It also produces
     * default nans.
     */
    fpst = *(float_status *)vst;
    set_default_nan_mode(true, &fpst);

    for (row = 0; row < oprsz; ) {
        uint16_t pa = pn[H2(row >> 4)];
        do {
            if (pa & 1) {
                void *vza_row = vza + tile_vslice_offset(row);
                uint32_t n = *(uint32_t *)(vzn + H1_4(row)) ^ neg;

                for (col = 0; col < oprsz; ) {
                    uint16_t pb = pm[H2(col >> 4)];
                    do {
                        if (pb & 1) {
                            uint32_t *a = vza_row + H1_4(col);
                            uint32_t *m = vzm + H1_4(col);
                            *a = float32_muladd(n, *m, *a, 0, vst);
                        }
                        col += 4;
                        pb >>= 4;
                    } while (col & 15);
                }
            }
            row += 4;
            pa >>= 4;
        } while (row & 15);
    }
}

