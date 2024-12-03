#pragma once
#include "jove/jove.h"

#include <string>

namespace jove {

void UnserializeJVFromFile(jv_t &out, jv_file_t &, const char *path, bool text = true);
void UnserializeJV(jv_t &out, jv_file_t &, std::istream &, bool text = true);
void SerializeJV(const jv_t &in, std::ostream &, bool text = true);
void SerializeJVToFile(const jv_t &in, const char *path, bool text = true);

}
