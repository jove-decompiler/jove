#include "crypto.h"
#include <rhash.h>
#include <llvm/ADT/StringExtras.h>
#include <stdexcept>

namespace jove {
namespace crypto {

std::string sha3(const void* message, size_t length) {
  static bool _Init = false;
  if (!_Init) {
    _Init = true;
    rhash_library_init();
  }

  unsigned char digest[64];

  if (rhash_msg(RHASH_SHA3_256, message, length, digest) < 0)
    throw std::runtime_error("rhash_msg failed");

  return llvm::toHex(llvm::StringRef((const char *)&digest[0], 32), true);
}

}
}
