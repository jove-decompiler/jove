#define TARGET_X86_64 1

#include <stdbool.h>

#include <stdint.h>

#include <stdlib.h>

typedef uint8_t flag;

typedef uint32_t float32;

typedef uint64_t float64;

typedef struct {
    uint64_t low;
    uint16_t high;
} floatx80;

enum {
    float_tininess_after_rounding  = 0,
    float_tininess_before_rounding = 1
};

enum {
    float_round_nearest_even = 0,
    float_round_down         = 1,
    float_round_up           = 2,
    float_round_to_zero      = 3,
    float_round_ties_away    = 4,
    /* Not an IEEE rounding mode: round to the closest odd mantissa value */
    float_round_to_odd       = 5,
};

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

static inline int clz64(uint64_t val)
{
    return val ? __builtin_clzll(val) : 64;
}

#define LIT64( a ) a##LL

floatx80 floatx80_sub(floatx80, floatx80, float_status *status);

static inline bool floatx80_invalid_encoding(floatx80 a)
{
    return (a.low & (1ULL << 63)) == 0 && (a.high & 0x7FFF) != 0;
}

static inline uint64_t extractFloatx80Frac(floatx80 a)
{
    return a.low;
}

static inline int32_t extractFloatx80Exp(floatx80 a)
{
    return a.high & 0x7FFF;
}

static inline flag extractFloatx80Sign(floatx80 a)
{
    return a.high >> 15;
}

static inline floatx80 packFloatx80(flag zSign, int32_t zExp, uint64_t zSig)
{
    floatx80 z;

    z.low = zSig;
    z.high = (((uint16_t)zSign) << 15) + zExp;
    return z;
}

# define SOFTFLOAT_GNUC_PREREQ(maj, min) \
         ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))

static inline void shift64RightJamming(uint64_t a, int count, uint64_t *zPtr)
{
    uint64_t z;

    if ( count == 0 ) {
        z = a;
    }
    else if ( count < 64 ) {
        z = ( a>>count ) | ( ( a<<( ( - count ) & 63 ) ) != 0 );
    }
    else {
        z = ( a != 0 );
    }
    *zPtr = z;

}

static inline void
 shift64ExtraRightJamming(
     uint64_t a0, uint64_t a1, int count, uint64_t *z0Ptr, uint64_t *z1Ptr)
{
    uint64_t z0, z1;
    int8_t negCount = ( - count ) & 63;

    if ( count == 0 ) {
        z1 = a1;
        z0 = a0;
    }
    else if ( count < 64 ) {
        z1 = ( a0<<negCount ) | ( a1 != 0 );
        z0 = a0>>count;
    }
    else {
        if ( count == 64 ) {
            z1 = a0 | ( a1 != 0 );
        }
        else {
            z1 = ( ( a0 | a1 ) != 0 );
        }
        z0 = 0;
    }
    *z1Ptr = z1;
    *z0Ptr = z0;

}

static inline void
 shift128RightJamming(
     uint64_t a0, uint64_t a1, int count, uint64_t *z0Ptr, uint64_t *z1Ptr)
{
    uint64_t z0, z1;
    int8_t negCount = ( - count ) & 63;

    if ( count == 0 ) {
        z1 = a1;
        z0 = a0;
    }
    else if ( count < 64 ) {
        z1 = ( a0<<negCount ) | ( a1>>count ) | ( ( a1<<negCount ) != 0 );
        z0 = a0>>count;
    }
    else {
        if ( count == 64 ) {
            z1 = a0 | ( a1 != 0 );
        }
        else if ( count < 128 ) {
            z1 = ( a0>>( count & 63 ) ) | ( ( ( a0<<negCount ) | a1 ) != 0 );
        }
        else {
            z1 = ( ( a0 | a1 ) != 0 );
        }
        z0 = 0;
    }
    *z1Ptr = z1;
    *z0Ptr = z0;

}

static inline void
 shortShift128Left(
     uint64_t a0, uint64_t a1, int count, uint64_t *z0Ptr, uint64_t *z1Ptr)
{

    *z1Ptr = a1<<count;
    *z0Ptr =
        ( count == 0 ) ? a0 : ( a0<<count ) | ( a1>>( ( - count ) & 63 ) );

}

static inline void
 sub128(
     uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1, uint64_t *z0Ptr, uint64_t *z1Ptr )
{

    *z1Ptr = a1 - b1;
    *z0Ptr = a0 - b0 - ( a1 < b1 );

}

static inline int8_t countLeadingZeros64(uint64_t a)
{
#if SOFTFLOAT_GNUC_PREREQ(3, 4)
    if (a) {
        return __builtin_clzll(a);
    } else {
        return 64;
    }
#else
    int8_t shiftCount;

    shiftCount = 0;
    if ( a < ( (uint64_t) 1 )<<32 ) {
        shiftCount += 32;
    }
    else {
        a >>= 32;
    }
    shiftCount += countLeadingZeros32( a );
    return shiftCount;
#endif
}

#define floatx80_infinity_high 0x7FFF

#define floatx80_infinity_low  LIT64(0x8000000000000000)

floatx80 floatx80_default_nan(float_status *status)
{
    floatx80 r;
#if defined(TARGET_M68K)
    r.low = LIT64(0xFFFFFFFFFFFFFFFF);
    r.high = 0x7FFF;
#else
    if (status->snan_bit_is_one) {
        r.low = LIT64(0xBFFFFFFFFFFFFFFF);
        r.high = 0x7FFF;
    } else {
        r.low = LIT64(0xC000000000000000);
        r.high = 0xFFFF;
    }
#endif
    return r;
}

void float_raise(uint8_t flags, float_status *status)
{
    status->float_exception_flags |= flags;
}

static int pickNaN(flag aIsQNaN, flag aIsSNaN, flag bIsQNaN, flag bIsSNaN,
                    flag aIsLargerSignificand)
{
    /* This implements x87 NaN propagation rules:
     * SNaN + QNaN => return the QNaN
     * two SNaNs => return the one with the larger significand, silenced
     * two QNaNs => return the one with the larger significand
     * SNaN and a non-NaN => return the SNaN, silenced
     * QNaN and a non-NaN => return the QNaN
     *
     * If we get down to comparing significands and they are the same,
     * return the NaN with the positive sign bit (if any).
     */
    if (aIsSNaN) {
        if (bIsSNaN) {
            return aIsLargerSignificand ? 0 : 1;
        }
        return bIsQNaN ? 1 : 0;
    } else if (aIsQNaN) {
        if (bIsSNaN || !bIsQNaN) {
            return 0;
        } else {
            return aIsLargerSignificand ? 0 : 1;
        }
    } else {
        return 1;
    }
}

int floatx80_is_quiet_nan(floatx80 a, float_status *status)
{
    if (status->snan_bit_is_one) {
        uint64_t aLow;

        aLow = a.low & ~0x4000000000000000ULL;
        return ((a.high & 0x7FFF) == 0x7FFF)
            && (aLow << 1)
            && (a.low == aLow);
    } else {
        return ((a.high & 0x7FFF) == 0x7FFF)
            && (LIT64(0x8000000000000000) <= ((uint64_t)(a.low << 1)));
    }
}

int floatx80_is_signaling_nan(floatx80 a, float_status *status)
{
    if (status->snan_bit_is_one) {
        return ((a.high & 0x7FFF) == 0x7FFF)
            && ((a.low << 1) >= 0x8000000000000000ULL);
    } else {
        uint64_t aLow;

        aLow = a.low & ~LIT64(0x4000000000000000);
        return ((a.high & 0x7FFF) == 0x7FFF)
            && (uint64_t)(aLow << 1)
            && (a.low == aLow);
    }
}

floatx80 floatx80_maybe_silence_nan(floatx80 a, float_status *status)
{
    if (floatx80_is_signaling_nan(a, status)) {
        if (status->snan_bit_is_one) {
            a = floatx80_default_nan(status);
        } else {
            a.low |= LIT64(0xC000000000000000);
            return a;
        }
    }
    return a;
}

floatx80 propagateFloatx80NaN(floatx80 a, floatx80 b, float_status *status)
{
    flag aIsQuietNaN, aIsSignalingNaN, bIsQuietNaN, bIsSignalingNaN;
    flag aIsLargerSignificand;

    aIsQuietNaN = floatx80_is_quiet_nan(a, status);
    aIsSignalingNaN = floatx80_is_signaling_nan(a, status);
    bIsQuietNaN = floatx80_is_quiet_nan(b, status);
    bIsSignalingNaN = floatx80_is_signaling_nan(b, status);

    if (aIsSignalingNaN | bIsSignalingNaN) {
        float_raise(float_flag_invalid, status);
    }

    if (status->default_nan_mode) {
        return floatx80_default_nan(status);
    }

    if (a.low < b.low) {
        aIsLargerSignificand = 0;
    } else if (b.low < a.low) {
        aIsLargerSignificand = 1;
    } else {
        aIsLargerSignificand = (a.high < b.high) ? 1 : 0;
    }

    if (pickNaN(aIsQuietNaN, aIsSignalingNaN, bIsQuietNaN, bIsSignalingNaN,
                aIsLargerSignificand)) {
        return floatx80_maybe_silence_nan(b, status);
    } else {
        return floatx80_maybe_silence_nan(a, status);
    }
}

void normalizeFloatx80Subnormal(uint64_t aSig, int32_t *zExpPtr,
                                uint64_t *zSigPtr)
{
    int8_t shiftCount;

    shiftCount = countLeadingZeros64( aSig );
    *zSigPtr = aSig<<shiftCount;
    *zExpPtr = 1 - shiftCount;
}

static void myabort(void) {
  __builtin_trap();
  __builtin_unreachable();
}

floatx80 roundAndPackFloatx80(int8_t roundingPrecision, flag zSign,
                              int32_t zExp, uint64_t zSig0, uint64_t zSig1,
                              float_status *status)
{
    int8_t roundingMode;
    flag roundNearestEven, increment, isTiny;
    int64_t roundIncrement, roundMask, roundBits;

    roundingMode = status->float_rounding_mode;
    roundNearestEven = ( roundingMode == float_round_nearest_even );
    if ( roundingPrecision == 80 ) goto precision80;
    if ( roundingPrecision == 64 ) {
        roundIncrement = LIT64( 0x0000000000000400 );
        roundMask = LIT64( 0x00000000000007FF );
    }
    else if ( roundingPrecision == 32 ) {
        roundIncrement = LIT64( 0x0000008000000000 );
        roundMask = LIT64( 0x000000FFFFFFFFFF );
    }
    else {
        goto precision80;
    }
    zSig0 |= ( zSig1 != 0 );
    switch (roundingMode) {
    case float_round_nearest_even:
    case float_round_ties_away:
        break;
    case float_round_to_zero:
        roundIncrement = 0;
        break;
    case float_round_up:
        roundIncrement = zSign ? 0 : roundMask;
        break;
    case float_round_down:
        roundIncrement = zSign ? roundMask : 0;
        break;
    default:
        myabort();
    }
    roundBits = zSig0 & roundMask;
    if ( 0x7FFD <= (uint32_t) ( zExp - 1 ) ) {
        if (    ( 0x7FFE < zExp )
             || ( ( zExp == 0x7FFE ) && ( zSig0 + roundIncrement < zSig0 ) )
           ) {
            goto overflow;
        }
        if ( zExp <= 0 ) {
            if (status->flush_to_zero) {
                float_raise(float_flag_output_denormal, status);
                return packFloatx80(zSign, 0, 0);
            }
            isTiny =
                   (status->float_detect_tininess
                    == float_tininess_before_rounding)
                || ( zExp < 0 )
                || ( zSig0 <= zSig0 + roundIncrement );
            shift64RightJamming( zSig0, 1 - zExp, &zSig0 );
            zExp = 0;
            roundBits = zSig0 & roundMask;
            if (isTiny && roundBits) {
                float_raise(float_flag_underflow, status);
            }
            if (roundBits) {
                status->float_exception_flags |= float_flag_inexact;
            }
            zSig0 += roundIncrement;
            if ( (int64_t) zSig0 < 0 ) zExp = 1;
            roundIncrement = roundMask + 1;
            if ( roundNearestEven && ( roundBits<<1 == roundIncrement ) ) {
                roundMask |= roundIncrement;
            }
            zSig0 &= ~ roundMask;
            return packFloatx80( zSign, zExp, zSig0 );
        }
    }
    if (roundBits) {
        status->float_exception_flags |= float_flag_inexact;
    }
    zSig0 += roundIncrement;
    if ( zSig0 < roundIncrement ) {
        ++zExp;
        zSig0 = LIT64( 0x8000000000000000 );
    }
    roundIncrement = roundMask + 1;
    if ( roundNearestEven && ( roundBits<<1 == roundIncrement ) ) {
        roundMask |= roundIncrement;
    }
    zSig0 &= ~ roundMask;
    if ( zSig0 == 0 ) zExp = 0;
    return packFloatx80( zSign, zExp, zSig0 );
 precision80:
    switch (roundingMode) {
    case float_round_nearest_even:
    case float_round_ties_away:
        increment = ((int64_t)zSig1 < 0);
        break;
    case float_round_to_zero:
        increment = 0;
        break;
    case float_round_up:
        increment = !zSign && zSig1;
        break;
    case float_round_down:
        increment = zSign && zSig1;
        break;
    default:
        myabort();
    }
    if ( 0x7FFD <= (uint32_t) ( zExp - 1 ) ) {
        if (    ( 0x7FFE < zExp )
             || (    ( zExp == 0x7FFE )
                  && ( zSig0 == LIT64( 0xFFFFFFFFFFFFFFFF ) )
                  && increment
                )
           ) {
            roundMask = 0;
 overflow:
            float_raise(float_flag_overflow | float_flag_inexact, status);
            if (    ( roundingMode == float_round_to_zero )
                 || ( zSign && ( roundingMode == float_round_up ) )
                 || ( ! zSign && ( roundingMode == float_round_down ) )
               ) {
                return packFloatx80( zSign, 0x7FFE, ~ roundMask );
            }
            return packFloatx80(zSign,
                                floatx80_infinity_high,
                                floatx80_infinity_low);
        }
        if ( zExp <= 0 ) {
            isTiny =
                   (status->float_detect_tininess
                    == float_tininess_before_rounding)
                || ( zExp < 0 )
                || ! increment
                || ( zSig0 < LIT64( 0xFFFFFFFFFFFFFFFF ) );
            shift64ExtraRightJamming( zSig0, zSig1, 1 - zExp, &zSig0, &zSig1 );
            zExp = 0;
            if (isTiny && zSig1) {
                float_raise(float_flag_underflow, status);
            }
            if (zSig1) {
                status->float_exception_flags |= float_flag_inexact;
            }
            switch (roundingMode) {
            case float_round_nearest_even:
            case float_round_ties_away:
                increment = ((int64_t)zSig1 < 0);
                break;
            case float_round_to_zero:
                increment = 0;
                break;
            case float_round_up:
                increment = !zSign && zSig1;
                break;
            case float_round_down:
                increment = zSign && zSig1;
                break;
            default:
                myabort();
            }
            if ( increment ) {
                ++zSig0;
                zSig0 &=
                    ~ ( ( (uint64_t) ( zSig1<<1 ) == 0 ) & roundNearestEven );
                if ( (int64_t) zSig0 < 0 ) zExp = 1;
            }
            return packFloatx80( zSign, zExp, zSig0 );
        }
    }
    if (zSig1) {
        status->float_exception_flags |= float_flag_inexact;
    }
    if ( increment ) {
        ++zSig0;
        if ( zSig0 == 0 ) {
            ++zExp;
            zSig0 = LIT64( 0x8000000000000000 );
        }
        else {
            zSig0 &= ~ ( ( (uint64_t) ( zSig1<<1 ) == 0 ) & roundNearestEven );
        }
    }
    else {
        if ( zSig0 == 0 ) zExp = 0;
    }
    return packFloatx80( zSign, zExp, zSig0 );

}

floatx80 normalizeRoundAndPackFloatx80(int8_t roundingPrecision,
                                       flag zSign, int32_t zExp,
                                       uint64_t zSig0, uint64_t zSig1,
                                       float_status *status)
{
    int8_t shiftCount;

    if ( zSig0 == 0 ) {
        zSig0 = zSig1;
        zSig1 = 0;
        zExp -= 64;
    }
    shiftCount = countLeadingZeros64( zSig0 );
    shortShift128Left( zSig0, zSig1, shiftCount, &zSig0, &zSig1 );
    zExp -= shiftCount;
    return roundAndPackFloatx80(roundingPrecision, zSign, zExp,
                                zSig0, zSig1, status);

}

static floatx80 addFloatx80Sigs(floatx80 a, floatx80 b, flag zSign,
                                float_status *status)
{
    int32_t aExp, bExp, zExp;
    uint64_t aSig, bSig, zSig0, zSig1;
    int32_t expDiff;

    aSig = extractFloatx80Frac( a );
    aExp = extractFloatx80Exp( a );
    bSig = extractFloatx80Frac( b );
    bExp = extractFloatx80Exp( b );
    expDiff = aExp - bExp;
    if ( 0 < expDiff ) {
        if ( aExp == 0x7FFF ) {
            if ((uint64_t)(aSig << 1)) {
                return propagateFloatx80NaN(a, b, status);
            }
            return a;
        }
        if ( bExp == 0 ) --expDiff;
        shift64ExtraRightJamming( bSig, 0, expDiff, &bSig, &zSig1 );
        zExp = aExp;
    }
    else if ( expDiff < 0 ) {
        if ( bExp == 0x7FFF ) {
            if ((uint64_t)(bSig << 1)) {
                return propagateFloatx80NaN(a, b, status);
            }
            return packFloatx80(zSign,
                                floatx80_infinity_high,
                                floatx80_infinity_low);
        }
        if ( aExp == 0 ) ++expDiff;
        shift64ExtraRightJamming( aSig, 0, - expDiff, &aSig, &zSig1 );
        zExp = bExp;
    }
    else {
        if ( aExp == 0x7FFF ) {
            if ( (uint64_t) ( ( aSig | bSig )<<1 ) ) {
                return propagateFloatx80NaN(a, b, status);
            }
            return a;
        }
        zSig1 = 0;
        zSig0 = aSig + bSig;
        if ( aExp == 0 ) {
            normalizeFloatx80Subnormal( zSig0, &zExp, &zSig0 );
            goto roundAndPack;
        }
        zExp = aExp;
        goto shiftRight1;
    }
    zSig0 = aSig + bSig;
    if ( (int64_t) zSig0 < 0 ) goto roundAndPack;
 shiftRight1:
    shift64ExtraRightJamming( zSig0, zSig1, 1, &zSig0, &zSig1 );
    zSig0 |= LIT64( 0x8000000000000000 );
    ++zExp;
 roundAndPack:
    return roundAndPackFloatx80(status->floatx80_rounding_precision,
                                zSign, zExp, zSig0, zSig1, status);
}

static floatx80 subFloatx80Sigs(floatx80 a, floatx80 b, flag zSign,
                                float_status *status)
{
    int32_t aExp, bExp, zExp;
    uint64_t aSig, bSig, zSig0, zSig1;
    int32_t expDiff;

    aSig = extractFloatx80Frac( a );
    aExp = extractFloatx80Exp( a );
    bSig = extractFloatx80Frac( b );
    bExp = extractFloatx80Exp( b );
    expDiff = aExp - bExp;
    if ( 0 < expDiff ) goto aExpBigger;
    if ( expDiff < 0 ) goto bExpBigger;
    if ( aExp == 0x7FFF ) {
        if ( (uint64_t) ( ( aSig | bSig )<<1 ) ) {
            return propagateFloatx80NaN(a, b, status);
        }
        float_raise(float_flag_invalid, status);
        return floatx80_default_nan(status);
    }
    if ( aExp == 0 ) {
        aExp = 1;
        bExp = 1;
    }
    zSig1 = 0;
    if ( bSig < aSig ) goto aBigger;
    if ( aSig < bSig ) goto bBigger;
    return packFloatx80(status->float_rounding_mode == float_round_down, 0, 0);
 bExpBigger:
    if ( bExp == 0x7FFF ) {
        if ((uint64_t)(bSig << 1)) {
            return propagateFloatx80NaN(a, b, status);
        }
        return packFloatx80(zSign ^ 1, floatx80_infinity_high,
                            floatx80_infinity_low);
    }
    if ( aExp == 0 ) ++expDiff;
    shift128RightJamming( aSig, 0, - expDiff, &aSig, &zSig1 );
 bBigger:
    sub128( bSig, 0, aSig, zSig1, &zSig0, &zSig1 );
    zExp = bExp;
    zSign ^= 1;
    goto normalizeRoundAndPack;
 aExpBigger:
    if ( aExp == 0x7FFF ) {
        if ((uint64_t)(aSig << 1)) {
            return propagateFloatx80NaN(a, b, status);
        }
        return a;
    }
    if ( bExp == 0 ) --expDiff;
    shift128RightJamming( bSig, 0, expDiff, &bSig, &zSig1 );
 aBigger:
    sub128( aSig, 0, bSig, zSig1, &zSig0, &zSig1 );
    zExp = aExp;
 normalizeRoundAndPack:
    return normalizeRoundAndPackFloatx80(status->floatx80_rounding_precision,
                                         zSign, zExp, zSig0, zSig1, status);
}

floatx80 floatx80_sub(floatx80 a, floatx80 b, float_status *status)
{
    flag aSign, bSign;

    if (floatx80_invalid_encoding(a) || floatx80_invalid_encoding(b)) {
        float_raise(float_flag_invalid, status);
        return floatx80_default_nan(status);
    }
    aSign = extractFloatx80Sign( a );
    bSign = extractFloatx80Sign( b );
    if ( aSign == bSign ) {
        return subFloatx80Sigs(a, b, aSign, status);
    }
    else {
        return addFloatx80Sigs(a, b, aSign, status);
    }

}

#define Q_TAILQ_ENTRY(type, qual)                                       \
struct {                                                                \
        qual type *tqe_next;            /* next element */              \
        qual type *qual *tqe_prev;      /* address of previous next element */\
}

#define QTAILQ_ENTRY(type)       Q_TAILQ_ENTRY(struct type,)

typedef struct MemTxAttrs {
    /* Bus masters which don't specify any attributes will get this
     * (via the MEMTXATTRS_UNSPECIFIED constant), so that we can
     * distinguish "all attributes deliberately clear" from
     * "didn't specify" if necessary.
     */
    unsigned int unspecified:1;
    /* ARM/AMBA: TrustZone Secure access
     * x86: System Management Mode access
     */
    unsigned int secure:1;
    /* Memory access is usermode (unprivileged) */
    unsigned int user:1;
    /* Requester ID (for MSI for example) */
    unsigned int requester_id:16;
} MemTxAttrs;

typedef uint64_t vaddr;

typedef struct CPUBreakpoint {
    vaddr pc;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUBreakpoint) entry;
} CPUBreakpoint;

struct CPUWatchpoint {
    vaddr _vaddr;
    vaddr len;
    vaddr hitaddr;
    MemTxAttrs hitattrs;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUWatchpoint) entry;
};

#define HV_X64_MSR_CRASH_P0                     0x40000100

#define HV_X64_MSR_CRASH_P4                     0x40000104

#define HV_CRASH_PARAMS    (HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 + 1)

#define HV_SINT_COUNT                         16

#define HV_STIMER_COUNT                       4

#define CPU_COMMON_TLB

#define CPU_COMMON                                                      \
    /* soft mmu support */                                              \
    CPU_COMMON_TLB

typedef uint64_t target_ulong;

#define MCE_BANKS_DEF   10

#define MSR_MTRRcap_VCNT                8

#define MSR_P6_EVNTSEL0                 0x186

#define MSR_IA32_PERF_STATUS            0x198

#define MAX_RTIT_ADDRS                  8

typedef enum FeatureWord {
    FEAT_1_EDX,         /* CPUID[1].EDX */
    FEAT_1_ECX,         /* CPUID[1].ECX */
    FEAT_7_0_EBX,       /* CPUID[EAX=7,ECX=0].EBX */
    FEAT_7_0_ECX,       /* CPUID[EAX=7,ECX=0].ECX */
    FEAT_7_0_EDX,       /* CPUID[EAX=7,ECX=0].EDX */
    FEAT_8000_0001_EDX, /* CPUID[8000_0001].EDX */
    FEAT_8000_0001_ECX, /* CPUID[8000_0001].ECX */
    FEAT_8000_0007_EDX, /* CPUID[8000_0007].EDX */
    FEAT_8000_0008_EBX, /* CPUID[8000_0008].EBX */
    FEAT_C000_0001_EDX, /* CPUID[C000_0001].EDX */
    FEAT_KVM,           /* CPUID[4000_0001].EAX (KVM_CPUID_FEATURES) */
    FEAT_KVM_HINTS,     /* CPUID[4000_0001].EDX */
    FEAT_HYPERV_EAX,    /* CPUID[4000_0003].EAX */
    FEAT_HYPERV_EBX,    /* CPUID[4000_0003].EBX */
    FEAT_HYPERV_EDX,    /* CPUID[4000_0003].EDX */
    FEAT_SVM,           /* CPUID[8000_000A].EDX */
    FEAT_XSAVE,         /* CPUID[EAX=0xd,ECX=1].EAX */
    FEAT_6_EAX,         /* CPUID[6].EAX */
    FEAT_XSAVE_COMP_LO, /* CPUID[EAX=0xd,ECX=0].EAX */
    FEAT_XSAVE_COMP_HI, /* CPUID[EAX=0xd,ECX=0].EDX */
    FEATURE_WORDS,
} FeatureWord;

typedef uint32_t FeatureWordArray[FEATURE_WORDS];

#define MMREG_UNION(n, bits)        \
    union n {                       \
        uint8_t  _b_##n[(bits)/8];  \
        uint16_t _w_##n[(bits)/16]; \
        uint32_t _l_##n[(bits)/32]; \
        uint64_t _q_##n[(bits)/64]; \
        float32  _s_##n[(bits)/32]; \
        float64  _d_##n[(bits)/64]; \
    }

typedef struct SegmentCache {
    uint32_t selector;
    target_ulong base;
    uint32_t limit;
    uint32_t flags;
} SegmentCache;

typedef union {
    uint8_t _b[16];
    uint16_t _w[8];
    uint32_t _l[4];
    uint64_t _q[2];
} XMMReg;

typedef union {
    uint8_t _b[32];
    uint16_t _w[16];
    uint32_t _l[8];
    uint64_t _q[4];
} YMMReg;

typedef MMREG_UNION(ZMMReg, 512) ZMMReg;

typedef MMREG_UNION(MMXReg, 64)  MMXReg;

typedef struct BNDReg {
    uint64_t lb;
    uint64_t ub;
} BNDReg;

typedef struct BNDCSReg {
    uint64_t cfgu;
    uint64_t sts;
} BNDCSReg;

typedef union {
    floatx80 d __attribute__((aligned(16)));
    MMXReg mmx;
} FPReg;

#define CPU_NB_REGS64 16

#define CPU_NB_REGS CPU_NB_REGS64

#define MAX_FIXED_COUNTERS 3

#define MAX_GP_COUNTERS    (MSR_IA32_PERF_STATUS - MSR_P6_EVNTSEL0)

#define NB_OPMASK_REGS 8

typedef struct {
    uint64_t base;
    uint64_t mask;
} MTRRVar;

typedef enum TPRAccess {
    TPR_ACCESS_READ,
    TPR_ACCESS_WRITE,
} TPRAccess;

typedef struct CPUX86State {
    /* standard registers */
    target_ulong regs[CPU_NB_REGS];
    target_ulong eip;
    target_ulong eflags; /* eflags register. During CPU emulation, CC
                        flags and DF are set to zero because they are
                        stored elsewhere */

    /* emulator internal eflags handling */
    target_ulong cc_dst;
    target_ulong cc_src;
    target_ulong cc_src2;
    uint32_t cc_op;
    int32_t df; /* D flag : 1 if D = 0, -1 if D = 1 */
    uint32_t hflags; /* TB flags, see HF_xxx constants. These flags
                        are known at translation time. */
    uint32_t hflags2; /* various other flags, see HF2_xxx constants. */

    /* segments */
    SegmentCache segs[6]; /* selector values */
    SegmentCache ldt;
    SegmentCache tr;
    SegmentCache gdt; /* only base and limit are used */
    SegmentCache idt; /* only base and limit are used */

    target_ulong cr[5]; /* NOTE: cr1 is unused */
    int32_t a20_mask;

    BNDReg bnd_regs[4];
    BNDCSReg bndcs_regs;
    uint64_t msr_bndcfgs;
    uint64_t efer;

    /* Beginning of state preserved by INIT (dummy marker).  */
    struct {} start_init_save;

    /* FPU state */
    unsigned int fpstt; /* top of stack index */
    uint16_t fpus;
    uint16_t fpuc;
    uint8_t fptags[8];   /* 0 = valid, 1 = empty */
    FPReg fpregs[8];
    /* KVM-only so far */
    uint16_t fpop;
    uint64_t fpip;
    uint64_t fpdp;

    /* emulator internal variables */
    float_status fp_status;
    floatx80 ft0;

    float_status mmx_status; /* for 3DNow! float ops */
    float_status sse_status;
    uint32_t mxcsr;
    ZMMReg xmm_regs[CPU_NB_REGS == 8 ? 8 : 32];
    ZMMReg xmm_t0;
    MMXReg mmx_t0;

    XMMReg ymmh_regs[CPU_NB_REGS];

    uint64_t opmask_regs[NB_OPMASK_REGS];
    YMMReg zmmh_regs[CPU_NB_REGS];
    ZMMReg hi16_zmm_regs[CPU_NB_REGS];

    /* sysenter registers */
    uint32_t sysenter_cs;
    target_ulong sysenter_esp;
    target_ulong sysenter_eip;
    uint64_t star;

    uint64_t vm_hsave;

#ifdef TARGET_X86_64
    target_ulong lstar;
    target_ulong cstar;
    target_ulong fmask;
    target_ulong kernelgsbase;
#endif

    uint64_t tsc;
    uint64_t tsc_adjust;
    uint64_t tsc_deadline;
    uint64_t tsc_aux;

    uint64_t xcr0;

    uint64_t mcg_status;
    uint64_t msr_ia32_misc_enable;
    uint64_t msr_ia32_feature_control;

    uint64_t msr_fixed_ctr_ctrl;
    uint64_t msr_global_ctrl;
    uint64_t msr_global_status;
    uint64_t msr_global_ovf_ctrl;
    uint64_t msr_fixed_counters[MAX_FIXED_COUNTERS];
    uint64_t msr_gp_counters[MAX_GP_COUNTERS];
    uint64_t msr_gp_evtsel[MAX_GP_COUNTERS];

    uint64_t pat;
    uint32_t smbase;
    uint64_t msr_smi_count;

    uint32_t pkru;

    uint64_t spec_ctrl;

    /* End of state preserved by INIT (dummy marker).  */
    struct {} end_init_save;

    uint64_t system_time_msr;
    uint64_t wall_clock_msr;
    uint64_t steal_time_msr;
    uint64_t async_pf_en_msr;
    uint64_t pv_eoi_en_msr;

    /* Partition-wide HV MSRs, will be updated only on the first vcpu */
    uint64_t msr_hv_hypercall;
    uint64_t msr_hv_guest_os_id;
    uint64_t msr_hv_tsc;

    /* Per-VCPU HV MSRs */
    uint64_t msr_hv_vapic;
    uint64_t msr_hv_crash_params[HV_CRASH_PARAMS];
    uint64_t msr_hv_runtime;
    uint64_t msr_hv_synic_control;
    uint64_t msr_hv_synic_evt_page;
    uint64_t msr_hv_synic_msg_page;
    uint64_t msr_hv_synic_sint[HV_SINT_COUNT];
    uint64_t msr_hv_stimer_config[HV_STIMER_COUNT];
    uint64_t msr_hv_stimer_count[HV_STIMER_COUNT];

    uint64_t msr_rtit_ctrl;
    uint64_t msr_rtit_status;
    uint64_t msr_rtit_output_base;
    uint64_t msr_rtit_output_mask;
    uint64_t msr_rtit_cr3_match;
    uint64_t msr_rtit_addrs[MAX_RTIT_ADDRS];

    /* exception/interrupt handling */
    int error_code;
    int exception_is_int;
    target_ulong exception_next_eip;
    target_ulong dr[8]; /* debug registers; note dr4 and dr5 are unused */
    union {
        struct CPUBreakpoint *cpu_breakpoint[4];
        struct CPUWatchpoint *cpu_watchpoint[4];
    }; /* break/watchpoints for dr[0..3] */
    int old_exception;  /* exception in flight */

    uint64_t vm_vmcb;
    uint64_t tsc_offset;
    uint64_t intercept;
    uint16_t intercept_cr_read;
    uint16_t intercept_cr_write;
    uint16_t intercept_dr_read;
    uint16_t intercept_dr_write;
    uint32_t intercept_exceptions;
    uint8_t v_tpr;

    /* KVM states, automatically cleared on reset */
    uint8_t nmi_injected;
    uint8_t nmi_pending;

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    CPU_COMMON

    /* Fields after CPU_COMMON are preserved across CPU reset. */

    /* processor features (e.g. for CPUID insn) */
    /* Minimum level/xlevel/xlevel2, based on CPU model + features */
    uint32_t cpuid_min_level, cpuid_min_xlevel, cpuid_min_xlevel2;
    /* Maximum level/xlevel/xlevel2 value for auto-assignment: */
    uint32_t cpuid_max_level, cpuid_max_xlevel, cpuid_max_xlevel2;
    /* Actual level/xlevel/xlevel2 value: */
    uint32_t cpuid_level, cpuid_xlevel, cpuid_xlevel2;
    uint32_t cpuid_vendor1;
    uint32_t cpuid_vendor2;
    uint32_t cpuid_vendor3;
    uint32_t cpuid_version;
    FeatureWordArray features;
    /* Features that were explicitly enabled/disabled */
    FeatureWordArray user_features;
    uint32_t cpuid_model[12];

    /* MTRRs */
    uint64_t mtrr_fixed[11];
    uint64_t mtrr_deftype;
    MTRRVar mtrr_var[MSR_MTRRcap_VCNT];

    /* For KVM */
    uint32_t mp_state;
    int32_t exception_injected;
    int32_t interrupt_injected;
    uint8_t soft_interrupt;
    uint8_t has_error_code;
    uint32_t ins_len;
    uint32_t sipi_vector;
    bool tsc_valid;
    int64_t tsc_khz;
    int64_t user_tsc_khz; /* for sanity check only */
    void *kvm_xsave_buf;
#if defined(CONFIG_HVF)
    HVFX86EmulatorState *hvf_emul;
#endif

    uint64_t mcg_cap;
    uint64_t mcg_ctl;
    uint64_t mcg_ext_ctl;
    uint64_t mce_banks[MCE_BANKS_DEF*4];
    uint64_t xstate_bv;

    /* vmstate */
    uint16_t fpus_vmstate;
    uint16_t fptag_vmstate;
    uint16_t fpregs_format_vmstate;

    uint64_t xss;

    TPRAccess tpr_access_type;
} CPUX86State;

#define ST0    (env->fpregs[env->fpstt].d)

#define ST(n)  (env->fpregs[(env->fpstt + (n)) & 7].d)

void helper_fsub_STN_ST0(CPUX86State *env, int st_index)
{
    ST(st_index) = floatx80_sub(ST(st_index), ST0, &env->fp_status);
}

