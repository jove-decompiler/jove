#pragma once
#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>
#include <concepts>

namespace jove {

template <std::unsigned_integral T>
[[nodiscard]] constexpr T align_down(T n, T m) noexcept {
  return (m == 0) ? n : (n / m) * m;
}

template <std::unsigned_integral T>
[[nodiscard]] constexpr T align_up(T n, T m) noexcept {
  if (m == 0)
    return n;
  const T r = n % m;
  return r == 0 ? n : (n + (m - r)); // beware of potential overflow
}

}
