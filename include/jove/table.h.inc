#ifndef IN_JOVE_H
#error "only to be included inline in jove/jove.h"
#endif

//
// this is a dangerous class. its primary use is for storing binaries. we can't
// use boost's static_vector, mostly because its size is not atomic, but also
// because the elements are required to be default-constructible (or take
// constexpr arguments).
//
template <typename T, std::size_t N>
struct table_t {
  alignas(T) std::byte storage_[N * sizeof(T)];
  std::atomic<uint32_t> len_ = 0;

  table_t(const table_t &) = delete;
  table_t &operator=(const table_t &) = delete;

  template <typename... Args>
  explicit table_t(Args &&...args) {
    for (std::size_t i = 0; i < N; ++i)
      new (&reinterpret_cast<T *>(storage_)[i]) T(std::forward<Args>(args)...);
  }

  ~table_t() {
    static_assert(std::is_nothrow_destructible_v<T>);

    for (std::size_t i = 0; i < N; ++i)
      reinterpret_cast<T *>(storage_)[i].~T();
  }

  unsigned size(void) const {
    return len_.load(std::memory_order_relaxed);
  }

  void clear(void) {
    len_.store(0, std::memory_order_relaxed);
  }

  // NO BOUNDS CHECKING!
  T &operator[](std::size_t i) {
    return reinterpret_cast<T *>(storage_)[i];
  }

  // NO BOUNDS CHECKING!
  const T &operator[](std::size_t i) const {
    return reinterpret_cast<const T *>(storage_)[i];
  }

  T &at(std::size_t i) {
    assert(i < size());
    return this->operator[](i);
  }

  const T &at(std::size_t i) const {
    assert(i < size());
    return this->operator[](i);
  }

  T *begin() { return reinterpret_cast<T *>(storage_); }
  T *end() { return &reinterpret_cast<T *>(storage_)[size()]; }

  const T *begin() const { return reinterpret_cast<const T *>(storage_); }
  const T *end() const { return &reinterpret_cast<const T *>(storage_)[size()]; }

  const T *cbegin() const { return reinterpret_cast<const T *>(storage_); }
  const T *cend() const { return &reinterpret_cast<const T *>(storage_)[size()]; }
};
