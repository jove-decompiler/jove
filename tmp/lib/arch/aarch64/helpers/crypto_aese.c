#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

#define HELPER(name) glue(helper_, name)

extern const uint8_t AES_sbox[256];

extern const uint8_t AES_isbox[256];

extern const uint8_t AES_shifts[16];

extern const uint8_t AES_ishifts[16];

#define CR_ST_BYTE(state, i)   (state.bytes[i])

union CRYPTO_STATE {
    uint8_t    bytes[16];
    uint32_t   words[4];
    uint64_t   l[2];
};

void HELPER(crypto_aese)(void *vd, void *vm, uint32_t decrypt)
{
    static uint8_t const * const sbox[2] = { AES_sbox, AES_isbox };
    static uint8_t const * const shift[2] = { AES_shifts, AES_ishifts };
    uint64_t *rd = vd;
    uint64_t *rm = vm;
    union CRYPTO_STATE rk = { .l = { rm[0], rm[1] } };
    union CRYPTO_STATE st = { .l = { rd[0], rd[1] } };
    int i;

    assert(decrypt < 2);

    /* xor state vector with round key */
    rk.l[0] ^= st.l[0];
    rk.l[1] ^= st.l[1];

    /* combine ShiftRows operation and sbox substitution */
    for (i = 0; i < 16; i++) {
        CR_ST_BYTE(st, i) = sbox[decrypt][CR_ST_BYTE(rk, shift[decrypt][i])];
    }

    rd[0] = st.l[0];
    rd[1] = st.l[1];
}

