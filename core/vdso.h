#pragma once
#include <string>
#include <string_view>

namespace jove {

std::string_view get_vdso(void); /* pointer to [vdso] */
bool capture_vdso(std::string &out);

}
