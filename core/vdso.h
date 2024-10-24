#pragma once
#include <string>
#include <string_view>

namespace jove {

std::string_view get_vdso(void); /* pointer to [vdso] */
std::string_view hallucinate_vdso(void);

template <typename StringTy>
bool capture_vdso(StringTy &out);

}
