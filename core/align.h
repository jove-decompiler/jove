#pragma once
#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>
#include <concepts>
#include <bit>

namespace jove {

template <std::unsigned_integral T>
static constexpr T align_down(T n, T m) noexcept {
  return (m == 0) ? n : (n / m) * m;
}

template <std::unsigned_integral T>
static constexpr T align_up(T n, T m) noexcept {
  return align_down((n) + (m) - 1, (m));
}

template <std::unsigned_integral T>
static constexpr T align_down_pow2(T n, T m) noexcept {
  return n & ~(m - 1);
}

template <std::unsigned_integral T, T M>
static constexpr T align_down_pow2_known(T n) noexcept {
  static_assert(std::has_single_bit(M));

  return n & ~(M - 1);
}

}
