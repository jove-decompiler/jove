#pragma once
#include <cerrno>
#include <concepts>
#include <functional>
#include <type_traits>
#include <utility>

namespace jove {
namespace sys {

template <class F, class... Args>
  requires std::is_integral_v<std::invoke_result_t<F, Args...>>
[[nodiscard]] inline auto retry_eintr(F &&f, Args &&...args)
    -> std::invoke_result_t<F, Args...> {
  using R = std::invoke_result_t<F, Args...>;
  R r;
  do {
    errno = 0; /* reset (paranoid) */
    r = std::invoke(std::forward<F>(f), std::forward<Args>(args)...);
  } while (r == static_cast<R>(-1) && errno == EINTR);

  return r;
}
}
}
