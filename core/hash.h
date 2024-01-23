#pragma once
#include "jove/types.h"

#include <string>
#include <string_view>

namespace jove {

hash_t hash_data(std::string_view data);
hash_t hash_file(const char *path);
std::string str_of_hash(const hash_t &);

}
