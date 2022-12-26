#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <llvm/ADT/StringExtras.h>
#include <stdexcept>

namespace jove {
namespace crypto {

std::string sha3(const void* data, size_t len) {
  uint8_t digest[SHA256_DIGEST_LENGTH];

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    throw std::runtime_error("EVP_MD_CTX_new failed");

  struct x {
    EVP_MD_CTX *ctx;

    x(EVP_MD_CTX *ctx) : ctx(ctx) {}
    ~x() { EVP_MD_CTX_destroy(ctx); }
  } __cleanup(ctx);

  if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1)
    throw std::runtime_error("EVP_DigestInit_ex failed");

  if (EVP_DigestUpdate(ctx, data, len) != 1)
    throw std::runtime_error("EVP_DigestUpdate failed");

  unsigned digest_length = sizeof(digest);
  if (EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1)
    throw std::runtime_error("EVP_DigestFinal_ex failed");

  return llvm::toHex(llvm::StringRef((const char *)&digest[0], sizeof(digest)), true);
}

}
}
