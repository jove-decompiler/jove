#include "hash.h"
#include "util.h"

#include <llvm/Support/SHA1.h>
#include <llvm/ADT/StringExtras.h>

#include <type_traits>

namespace jove {

hash_t hash_data(std::string_view sv) {
  std::array<uint8_t, 20> raw_hash = llvm::SHA1::hash(
      llvm::ArrayRef<uint8_t>((const uint8_t *)sv.data(), sv.size()));

  static_assert(sizeof(hash_t) <= 20);

  return *((const hash_t *)raw_hash.data());
}

hash_t hash_file(const char *path) {
  std::string buff;
  read_file_into_thing(path, buff);

  return hash_data(buff);
}

std::string str_of_hash(hash_t h) {
  return llvm::toHex(llvm::ArrayRef<uint8_t>((const uint8_t *)&h, sizeof(h)),
                     true);
}

} // namespace jove
