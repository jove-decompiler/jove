#include <string>
#include <cstdint>
#include <llvm/ADT/ArrayRef.h>

namespace jove {
namespace crypto {

typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u32 __le32;
typedef __u64 __le64;
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

static __attribute__((always_inline)) __u64 __le64_to_cpup(const __le64 *p) {
  return (__u64)*p;
}

static inline __u64 rol64(__u64 word, unsigned int shift) {
  return (word << shift) | (word >> (64 - shift));
}

constexpr unsigned SHA3_256_DIGEST_SIZE = 256 / 8;
constexpr unsigned SHA3_224_DIGEST_SIZE = 224 / 8;
constexpr unsigned SHA3_224_BLOCK_SIZE = 200 - 2 * SHA3_224_DIGEST_SIZE;

struct sha3_state {
  u64 st[25];
  unsigned int rsiz;
  unsigned int rsizw;

  unsigned int partial;
  u8 buf[SHA3_224_BLOCK_SIZE];
};

static __attribute__((always_inline)) u64 get_unaligned_le64(const void *p)
{
	return __le64_to_cpup((__le64 *)p);
}

static __attribute__((always_inline)) void put_unaligned_le32(u32 val, void *p)
{
	*((__le32 *)p) = val;
}

static __attribute__((always_inline)) void put_unaligned_le64(u64 val, void *p)
{
	*((__le64 *)p) = val;
}

constexpr unsigned KECCAK_ROUNDS = 24;

static const u64 keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

static void keccakf_round(u64 st[25])
{
	u64 t[5], tt, bc[5];

	/* Theta */
	bc[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
	bc[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
	bc[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
	bc[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
	bc[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

	t[0] = bc[4] ^ rol64(bc[1], 1);
	t[1] = bc[0] ^ rol64(bc[2], 1);
	t[2] = bc[1] ^ rol64(bc[3], 1);
	t[3] = bc[2] ^ rol64(bc[4], 1);
	t[4] = bc[3] ^ rol64(bc[0], 1);

	st[0] ^= t[0];

	/* Rho Pi */
	tt = st[1];
	st[ 1] = rol64(st[ 6] ^ t[1], 44);
	st[ 6] = rol64(st[ 9] ^ t[4], 20);
	st[ 9] = rol64(st[22] ^ t[2], 61);
	st[22] = rol64(st[14] ^ t[4], 39);
	st[14] = rol64(st[20] ^ t[0], 18);
	st[20] = rol64(st[ 2] ^ t[2], 62);
	st[ 2] = rol64(st[12] ^ t[2], 43);
	st[12] = rol64(st[13] ^ t[3], 25);
	st[13] = rol64(st[19] ^ t[4],  8);
	st[19] = rol64(st[23] ^ t[3], 56);
	st[23] = rol64(st[15] ^ t[0], 41);
	st[15] = rol64(st[ 4] ^ t[4], 27);
	st[ 4] = rol64(st[24] ^ t[4], 14);
	st[24] = rol64(st[21] ^ t[1],  2);
	st[21] = rol64(st[ 8] ^ t[3], 55);
	st[ 8] = rol64(st[16] ^ t[1], 45);
	st[16] = rol64(st[ 5] ^ t[0], 36);
	st[ 5] = rol64(st[ 3] ^ t[3], 28);
	st[ 3] = rol64(st[18] ^ t[3], 21);
	st[18] = rol64(st[17] ^ t[2], 15);
	st[17] = rol64(st[11] ^ t[1], 10);
	st[11] = rol64(st[ 7] ^ t[2],  6);
	st[ 7] = rol64(st[10] ^ t[0],  3);
	st[10] = rol64(    tt ^ t[1],  1);

	/* Chi */
	bc[ 0] = ~st[ 1] & st[ 2];
	bc[ 1] = ~st[ 2] & st[ 3];
	bc[ 2] = ~st[ 3] & st[ 4];
	bc[ 3] = ~st[ 4] & st[ 0];
	bc[ 4] = ~st[ 0] & st[ 1];
	st[ 0] ^= bc[ 0];
	st[ 1] ^= bc[ 1];
	st[ 2] ^= bc[ 2];
	st[ 3] ^= bc[ 3];
	st[ 4] ^= bc[ 4];

	bc[ 0] = ~st[ 6] & st[ 7];
	bc[ 1] = ~st[ 7] & st[ 8];
	bc[ 2] = ~st[ 8] & st[ 9];
	bc[ 3] = ~st[ 9] & st[ 5];
	bc[ 4] = ~st[ 5] & st[ 6];
	st[ 5] ^= bc[ 0];
	st[ 6] ^= bc[ 1];
	st[ 7] ^= bc[ 2];
	st[ 8] ^= bc[ 3];
	st[ 9] ^= bc[ 4];

	bc[ 0] = ~st[11] & st[12];
	bc[ 1] = ~st[12] & st[13];
	bc[ 2] = ~st[13] & st[14];
	bc[ 3] = ~st[14] & st[10];
	bc[ 4] = ~st[10] & st[11];
	st[10] ^= bc[ 0];
	st[11] ^= bc[ 1];
	st[12] ^= bc[ 2];
	st[13] ^= bc[ 3];
	st[14] ^= bc[ 4];

	bc[ 0] = ~st[16] & st[17];
	bc[ 1] = ~st[17] & st[18];
	bc[ 2] = ~st[18] & st[19];
	bc[ 3] = ~st[19] & st[15];
	bc[ 4] = ~st[15] & st[16];
	st[15] ^= bc[ 0];
	st[16] ^= bc[ 1];
	st[17] ^= bc[ 2];
	st[18] ^= bc[ 3];
	st[19] ^= bc[ 4];

	bc[ 0] = ~st[21] & st[22];
	bc[ 1] = ~st[22] & st[23];
	bc[ 2] = ~st[23] & st[24];
	bc[ 3] = ~st[24] & st[20];
	bc[ 4] = ~st[20] & st[21];
	st[20] ^= bc[ 0];
	st[21] ^= bc[ 1];
	st[22] ^= bc[ 2];
	st[23] ^= bc[ 3];
	st[24] ^= bc[ 4];
}

static void keccakf(u64 st[25]) {
  int round;

#pragma unroll
  for (round = 0; round < KECCAK_ROUNDS; round++) {
    keccakf_round(st);
    /* Iota */
    st[0] ^= keccakf_rndc[round];
  }
}

static void sha3_256_init(struct sha3_state *sctx) {
  unsigned int digest_size = SHA3_256_DIGEST_SIZE;

  sctx->rsiz = 200 - 2 * digest_size;
  sctx->rsizw = sctx->rsiz / 8;
  sctx->partial = 0;

  memset(sctx->st, 0, sizeof(sctx->st));
}

static int sha3_256_update(struct sha3_state *sctx,
                           const u8 *data,
                           unsigned int len) {
  unsigned int done;
  const u8 *src;

  done = 0;
  src = data;

  if ((sctx->partial + len) > (sctx->rsiz - 1)) {
    if (sctx->partial) {
      done = -sctx->partial;
      memcpy(sctx->buf + sctx->partial, data, done + sctx->rsiz);
      src = sctx->buf;
    }

    do {
      unsigned int i;

      for (i = 0; i < sctx->rsizw; i++)
        sctx->st[i] ^= get_unaligned_le64(src + 8 * i);
      keccakf(sctx->st);

      done += sctx->rsiz;
      src = data + done;
    } while (done + (sctx->rsiz - 1) < len);

    sctx->partial = 0;
  }
  memcpy(sctx->buf + sctx->partial, src, len - done);
  sctx->partial += (len - done);

  return 0;
}

static void sha3_256_final(struct sha3_state *sctx, u8 *out) {
  unsigned int i, inlen = sctx->partial;
  constexpr unsigned digest_size = SHA3_256_DIGEST_SIZE;
  __le64 *digest = (__le64 *)out;

  sctx->buf[inlen++] = 0x06;
  memset(sctx->buf + inlen, 0, sctx->rsiz - inlen);
  sctx->buf[sctx->rsiz - 1] |= 0x80;

  for (i = 0; i < sctx->rsizw; i++)
    sctx->st[i] ^= get_unaligned_le64(sctx->buf + 8 * i);

  keccakf(sctx->st);

  for (i = 0; i < digest_size / 8; i++)
    put_unaligned_le64(sctx->st[i], digest++);

  if (digest_size & 4)
    put_unaligned_le32(sctx->st[i], (__le32 *)digest);

  memset(sctx, 0, sizeof(*sctx));
}

}

static const char byte_to_hexchars[256][2] = {
    {'0', '0'}, {'0', '1'}, {'0', '2'}, {'0', '3'}, {'0', '4'}, {'0', '5'},
    {'0', '6'}, {'0', '7'}, {'0', '8'}, {'0', '9'}, {'0', 'a'}, {'0', 'b'},
    {'0', 'c'}, {'0', 'd'}, {'0', 'e'}, {'0', 'f'}, {'1', '0'}, {'1', '1'},
    {'1', '2'}, {'1', '3'}, {'1', '4'}, {'1', '5'}, {'1', '6'}, {'1', '7'},
    {'1', '8'}, {'1', '9'}, {'1', 'a'}, {'1', 'b'}, {'1', 'c'}, {'1', 'd'},
    {'1', 'e'}, {'1', 'f'}, {'2', '0'}, {'2', '1'}, {'2', '2'}, {'2', '3'},
    {'2', '4'}, {'2', '5'}, {'2', '6'}, {'2', '7'}, {'2', '8'}, {'2', '9'},
    {'2', 'a'}, {'2', 'b'}, {'2', 'c'}, {'2', 'd'}, {'2', 'e'}, {'2', 'f'},
    {'3', '0'}, {'3', '1'}, {'3', '2'}, {'3', '3'}, {'3', '4'}, {'3', '5'},
    {'3', '6'}, {'3', '7'}, {'3', '8'}, {'3', '9'}, {'3', 'a'}, {'3', 'b'},
    {'3', 'c'}, {'3', 'd'}, {'3', 'e'}, {'3', 'f'}, {'4', '0'}, {'4', '1'},
    {'4', '2'}, {'4', '3'}, {'4', '4'}, {'4', '5'}, {'4', '6'}, {'4', '7'},
    {'4', '8'}, {'4', '9'}, {'4', 'a'}, {'4', 'b'}, {'4', 'c'}, {'4', 'd'},
    {'4', 'e'}, {'4', 'f'}, {'5', '0'}, {'5', '1'}, {'5', '2'}, {'5', '3'},
    {'5', '4'}, {'5', '5'}, {'5', '6'}, {'5', '7'}, {'5', '8'}, {'5', '9'},
    {'5', 'a'}, {'5', 'b'}, {'5', 'c'}, {'5', 'd'}, {'5', 'e'}, {'5', 'f'},
    {'6', '0'}, {'6', '1'}, {'6', '2'}, {'6', '3'}, {'6', '4'}, {'6', '5'},
    {'6', '6'}, {'6', '7'}, {'6', '8'}, {'6', '9'}, {'6', 'a'}, {'6', 'b'},
    {'6', 'c'}, {'6', 'd'}, {'6', 'e'}, {'6', 'f'}, {'7', '0'}, {'7', '1'},
    {'7', '2'}, {'7', '3'}, {'7', '4'}, {'7', '5'}, {'7', '6'}, {'7', '7'},
    {'7', '8'}, {'7', '9'}, {'7', 'a'}, {'7', 'b'}, {'7', 'c'}, {'7', 'd'},
    {'7', 'e'}, {'7', 'f'}, {'8', '0'}, {'8', '1'}, {'8', '2'}, {'8', '3'},
    {'8', '4'}, {'8', '5'}, {'8', '6'}, {'8', '7'}, {'8', '8'}, {'8', '9'},
    {'8', 'a'}, {'8', 'b'}, {'8', 'c'}, {'8', 'd'}, {'8', 'e'}, {'8', 'f'},
    {'9', '0'}, {'9', '1'}, {'9', '2'}, {'9', '3'}, {'9', '4'}, {'9', '5'},
    {'9', '6'}, {'9', '7'}, {'9', '8'}, {'9', '9'}, {'9', 'a'}, {'9', 'b'},
    {'9', 'c'}, {'9', 'd'}, {'9', 'e'}, {'9', 'f'}, {'a', '0'}, {'a', '1'},
    {'a', '2'}, {'a', '3'}, {'a', '4'}, {'a', '5'}, {'a', '6'}, {'a', '7'},
    {'a', '8'}, {'a', '9'}, {'a', 'a'}, {'a', 'b'}, {'a', 'c'}, {'a', 'd'},
    {'a', 'e'}, {'a', 'f'}, {'b', '0'}, {'b', '1'}, {'b', '2'}, {'b', '3'},
    {'b', '4'}, {'b', '5'}, {'b', '6'}, {'b', '7'}, {'b', '8'}, {'b', '9'},
    {'b', 'a'}, {'b', 'b'}, {'b', 'c'}, {'b', 'd'}, {'b', 'e'}, {'b', 'f'},
    {'c', '0'}, {'c', '1'}, {'c', '2'}, {'c', '3'}, {'c', '4'}, {'c', '5'},
    {'c', '6'}, {'c', '7'}, {'c', '8'}, {'c', '9'}, {'c', 'a'}, {'c', 'b'},
    {'c', 'c'}, {'c', 'd'}, {'c', 'e'}, {'c', 'f'}, {'d', '0'}, {'d', '1'},
    {'d', '2'}, {'d', '3'}, {'d', '4'}, {'d', '5'}, {'d', '6'}, {'d', '7'},
    {'d', '8'}, {'d', '9'}, {'d', 'a'}, {'d', 'b'}, {'d', 'c'}, {'d', 'd'},
    {'d', 'e'}, {'d', 'f'}, {'e', '0'}, {'e', '1'}, {'e', '2'}, {'e', '3'},
    {'e', '4'}, {'e', '5'}, {'e', '6'}, {'e', '7'}, {'e', '8'}, {'e', '9'},
    {'e', 'a'}, {'e', 'b'}, {'e', 'c'}, {'e', 'd'}, {'e', 'e'}, {'e', 'f'},
    {'f', '0'}, {'f', '1'}, {'f', '2'}, {'f', '3'}, {'f', '4'}, {'f', '5'},
    {'f', '6'}, {'f', '7'}, {'f', '8'}, {'f', '9'}, {'f', 'a'}, {'f', 'b'},
    {'f', 'c'}, {'f', 'd'}, {'f', 'e'}, {'f', 'f'}};

template <typename T>
static std::string sha3(const T &arr) {
  crypto::sha3_state sctx;

  crypto::sha3_256_init(&sctx);
  crypto::sha3_256_update(&sctx, (const crypto::u8 *)arr.data(), arr.size());
  crypto::u8 digest[crypto::SHA3_256_DIGEST_SIZE];
  crypto::sha3_256_final(&sctx, digest);

  std::string res;
  res.reserve(2 * crypto::SHA3_256_DIGEST_SIZE);

#pragma unroll
  for (unsigned i = 0; i < crypto::SHA3_256_DIGEST_SIZE; ++i) {
    res += byte_to_hexchars[digest[i]][0];
    res += byte_to_hexchars[digest[i]][1];
  }

  return res;
}

}
