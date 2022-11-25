#pragma once
#include "jove/jove.h"

#include <string>

namespace jove {

void ReadJvFromFile(const std::string &path, jv_t &out);
void WriteJvToFile(const std::string &path, const jv_t &in);

}
