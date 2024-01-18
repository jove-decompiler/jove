#pragma once
#include <string>
#include <string_view>

namespace jove {

typedef unsigned _BitInt(128) hash_t;

hash_t hash_data(std::string_view data);
hash_t hash_file(const char *path);
std::string str_of_hash(hash_t);

}
