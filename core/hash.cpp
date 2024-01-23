#include "hash.h"
#include "util.h"

#include <llvm/Support/SHA1.h>
#include <llvm/ADT/StringExtras.h>

#include <type_traits>

namespace jove {

hash_t hash_data(std::string_view sv) {
  return llvm::SHA1::hash(llvm::ArrayRef<uint8_t>((const uint8_t *)sv.data(),
                                                  sv.size()));
}

hash_t hash_file(const char *path) {
  std::string buff;
  read_file_into_thing(path, buff);

  return hash_data(buff);
}

std::string str_of_hash(const hash_t &h) { return llvm::toHex(h, true); }

} // namespace jove
