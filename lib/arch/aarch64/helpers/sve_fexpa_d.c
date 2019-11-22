#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

void HELPER(sve_fexpa_d)(void *vd, void *vn, uint32_t desc)
{
    /* These constants are cut-and-paste directly from the ARM pseudocode.  */
    static const uint64_t coeff[] = {
        0x0000000000000ull, 0x02C9A3E778061ull, 0x059B0D3158574ull,
        0x0874518759BC8ull, 0x0B5586CF9890Full, 0x0E3EC32D3D1A2ull,
        0x11301D0125B51ull, 0x1429AAEA92DE0ull, 0x172B83C7D517Bull,
        0x1A35BEB6FCB75ull, 0x1D4873168B9AAull, 0x2063B88628CD6ull,
        0x2387A6E756238ull, 0x26B4565E27CDDull, 0x29E9DF51FDEE1ull,
        0x2D285A6E4030Bull, 0x306FE0A31B715ull, 0x33C08B26416FFull,
        0x371A7373AA9CBull, 0x3A7DB34E59FF7ull, 0x3DEA64C123422ull,
        0x4160A21F72E2Aull, 0x44E086061892Dull, 0x486A2B5C13CD0ull,
        0x4BFDAD5362A27ull, 0x4F9B2769D2CA7ull, 0x5342B569D4F82ull,
        0x56F4736B527DAull, 0x5AB07DD485429ull, 0x5E76F15AD2148ull,
        0x6247EB03A5585ull, 0x6623882552225ull, 0x6A09E667F3BCDull,
        0x6DFB23C651A2Full, 0x71F75E8EC5F74ull, 0x75FEB564267C9ull,
        0x7A11473EB0187ull, 0x7E2F336CF4E62ull, 0x82589994CCE13ull,
        0x868D99B4492EDull, 0x8ACE5422AA0DBull, 0x8F1AE99157736ull,
        0x93737B0CDC5E5ull, 0x97D829FDE4E50ull, 0x9C49182A3F090ull,
        0xA0C667B5DE565ull, 0xA5503B23E255Dull, 0xA9E6B5579FDBFull,
        0xAE89F995AD3ADull, 0xB33A2B84F15FBull, 0xB7F76F2FB5E47ull,
        0xBCC1E904BC1D2ull, 0xC199BDD85529Cull, 0xC67F12E57D14Bull,
        0xCB720DCEF9069ull, 0xD072D4A07897Cull, 0xD5818DCFBA487ull,
        0xDA9E603DB3285ull, 0xDFC97337B9B5Full, 0xE502EE78B3FF6ull,
        0xEA4AFA2A490DAull, 0xEFA1BEE615A27ull, 0xF50765B6E4540ull,
        0xFA7C1819E90D8ull,
    };
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn;

    for (i = 0; i < opr_sz; i++) {
        uint64_t nn = n[i];
        intptr_t idx = extract32(nn, 0, 6);
        uint64_t exp = extract32(nn, 6, 11);
        d[i] = coeff[idx] | (exp << 52);
    }
}

