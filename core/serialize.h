#pragma once
#include "jove/jove.h"

#include <string>

namespace jove {

template <bool MT>
void UnserializeJVFromFile(jv_base_t<MT> &out, jv_file_t &, const char *path,
                           bool text = true);
template <bool MT>
void UnserializeJV(jv_base_t<MT> &out, jv_file_t &, std::istream &, bool text = true);
template <bool MT>
void SerializeJV(const jv_base_t<MT> &in, jv_file_t &, std::ostream &,
                 bool text = true);
template <bool MT>
void SerializeJVToFile(const jv_base_t<MT> &in, jv_file_t &, const char *path,
                       bool text = true);
}
