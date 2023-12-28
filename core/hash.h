#pragma once
#include <cstddef>
#include <string>

namespace jove {

typedef _BitInt(128) hash_t;

hash_t hash_data(const void *data, size_t len);
hash_t hash_file(const char *path);
std::string str_of_hash(hash_t);

}
