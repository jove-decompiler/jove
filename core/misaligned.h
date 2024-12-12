#pragma once
#include <type_traits>
#include <utility>

namespace jove {
namespace misaligned {

template <typename T>
__attribute__((pure)) inline T load(const void *p) noexcept {
  static_assert(std::is_trivially_copyable_v<T>,
                "T must be trivially copyable");
  T result;
  std::memcpy(&result, p, sizeof(T));
  return result;
}

}
}

#define JOVE_MISALIGNED_LOAD(x)                                                \
  misaligned::load<std::remove_cvref_t<decltype(x)>>(                          \
      reinterpret_cast<const void *>(std::addressof((x))))
