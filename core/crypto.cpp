#include "crypto.h"

#include <llvm/Support/SHA1.h>
#include <llvm/ADT/StringExtras.h>

namespace jove {
namespace crypto {

std::string hash(const void *data, size_t len) {
  llvm::SHA1 Hasher;
  Hasher.update(llvm::StringRef((const char *)data, len));
  return llvm::toHex(Hasher.final(), true);
}

}
}
