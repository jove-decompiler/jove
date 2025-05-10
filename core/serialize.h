#pragma once
#include "jove/jove.h"

#include <string>

namespace jove {

template <bool MT, bool MinSize>
void UnserializeJVFromFile(jv_base_t<MT, MinSize> &out,
			   jv_file_t &,
                           const char *path,
			   bool text = true);
template <bool MT, bool MinSize>
void UnserializeJV(jv_base_t<MT, MinSize> &out,
		   jv_file_t &,
		   std::istream &,
                   bool text);
template <bool MT, bool MinSize>
void SerializeJV(const jv_base_t<MT, MinSize> &in,
		 jv_file_t &,
		 std::ostream &,
                 bool text = true);
template <bool MT, bool MinSize>
void SerializeJVToFile(const jv_base_t<MT, MinSize> &in,
		       jv_file_t &,
                       const char *path,
		       bool text);
}
