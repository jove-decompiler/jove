#pragma once
#include "assert.h"

#include <cstdint>
#include <cstddef>

#include <sys/mman.h>

namespace jove {

class scoped_mmap {
  const size_t len = 0;
  void *const ptr = nullptr;

public:
  scoped_mmap() = delete;
  scoped_mmap(const scoped_mmap &) = delete;
  scoped_mmap &operator=(const scoped_mmap &) = delete;
  scoped_mmap(scoped_mmap &&) = delete;
  scoped_mmap &operator=(scoped_mmap &&) = delete;

  explicit scoped_mmap(void *addr, size_t len, int prot, int flags, int fd,
                       uint64_t off) noexcept
      : len(len), ptr(::mmap(addr, len, prot, flags, fd, off)) {}

  ~scoped_mmap() noexcept(false) { /* throws if failed to unmap memory */
    if (*this)
      aassert(::munmap(ptr, len) == 0);
  }

  explicit operator bool(void) const { return ptr && ptr != MAP_FAILED; }

  [[clang::always_inline]] void *get(void) const noexcept(false) {
    void *const res = this->ptr;

    aassert(res != MAP_FAILED);
    __builtin_assume(res != MAP_FAILED);
    return res;
  }
  [[clang::always_inline]] size_t size(void) const noexcept(false) {
    const size_t res = this->len;

    aassert(this->ptr != MAP_FAILED);
    __builtin_assume(res > 0u);

    return res;
  }
};

}
