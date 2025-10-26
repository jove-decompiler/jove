#pragma once
#include "assert.h"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

namespace jove {

//
// fancy pointers are how we implement a tagged std::unique_ptr.
//

template <class T, std::size_t N>
struct tagged_ptr2 {
  static_assert(std::countr_zero(alignof(T)) >= N,
                "N too large for adopt-by-fancy-pointer");

  static constexpr std::size_t align = std::size_t{1} << N;
  static constexpr std::uintptr_t tag_mask = align - 1;

  std::uintptr_t v = 0;

  tagged_ptr2() = default;
  tagged_ptr2(std::nullptr_t) : v(0) {}

  explicit tagged_ptr2(T *p) : v(reinterpret_cast<std::uintptr_t>(p)) {
    assert(std::countr_zero(reinterpret_cast<std::uintptr_t>(p)) >= N &&
           "insufficient natural alignment for requested tag bits");
  }

  T *untag() const noexcept { return reinterpret_cast<T *>(v & ~tag_mask); }

  std::uintptr_t tag() const noexcept { return v & tag_mask; }
  void set_tag(std::uintptr_t t) noexcept {
    v = (v & ~tag_mask) | (t & tag_mask);
  }

  explicit operator bool() const noexcept { return untag() != nullptr; }
  operator T *() const noexcept { return untag(); }
  T *operator->() const noexcept { return untag(); }
  T &operator*() const noexcept { return *untag(); }

  friend T *to_address(tagged_ptr2 p) noexcept { return p.untag(); }
};

template <class T, std::size_t N>
struct tagged_ptr2_delete {
  using pointer = tagged_ptr2<T, N>;

  void operator()(pointer p) const noexcept {
    if (auto *q = p.untag()) {
      delete q;
    }
  }
};

template <class T, std::size_t N>
using tagged_unique_ptr2 = std::unique_ptr<T, tagged_ptr2_delete<T, N>>;

//
// convenience
//
template <class T, std::size_t N>
inline tagged_unique_ptr2<T, N> adopt_with_tag(T *raw, std::uintptr_t tag) {
  using del_t = tagged_ptr2_delete<T, N>;
  typename del_t::pointer tp(raw);
  tp.set_tag(tag);
  return tagged_unique_ptr2<T, N>(tp);
}

template <class T, std::size_t N>
struct tagged_reference_wrapper2 {
  using type    = T;
  using pointer = tagged_ptr2<std::remove_reference_t<T>, N>;

private:
  pointer p;

public:
  tagged_reference_wrapper2() = delete;

  tagged_reference_wrapper2 *operator&() = delete;             /* catch bugs */
  const tagged_reference_wrapper2 *operator&() const = delete; /* catch bugs */

  explicit tagged_reference_wrapper2(T &t, std::uintptr_t tag = 0) noexcept
      : p(&t) {
    this->p.set_tag(tag);
  }

  tagged_reference_wrapper2(pointer tp) noexcept { this->p = tp; }
  tagged_reference_wrapper2& operator=(pointer other) noexcept {
    this->p = other;
  }

  tagged_reference_wrapper2(const tagged_reference_wrapper2 &) noexcept = default;
  tagged_reference_wrapper2& operator=(const tagged_reference_wrapper2 &) noexcept = default;

  pointer ptr(void) const noexcept { return this->p; }

  operator T &() const noexcept { return *this->p.untag(); }
  T &get() const noexcept { return *this->p.untag(); }

  template <class... Args>
  decltype(auto) operator()(Args &&...args) const
      noexcept(noexcept(std::invoke(get(), std::forward<Args>(args)...))) {
    return std::invoke(get(), std::forward<Args>(args)...);
  }

  std::uintptr_t tag() const noexcept { return this->p.tag(); }
  void set_tag(std::uintptr_t t) noexcept { this->p.set_tag(t); }

  friend T *to_address(tagged_reference_wrapper2 r) noexcept {
    return r.p.untag();
  }

  friend bool operator==(const tagged_reference_wrapper2 a,
                         const tagged_reference_wrapper2 b) noexcept {
    return a.p.untag() == b.p.untag() && a.tag() == b.tag();
  }
  friend bool operator!=(const tagged_reference_wrapper2 a,
                         const tagged_reference_wrapper2 b) noexcept {
    return !(a == b);
  }
};

}
