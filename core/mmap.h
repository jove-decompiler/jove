#pragma once
#include "jove/macros.h"

#include <cstdint>
#include <cstddef>

#include <sys/mman.h>

namespace jove {

struct scoped_mmap {
  const size_t len = 0;
  void *const ptr = nullptr;

  scoped_mmap() = delete;
  scoped_mmap(const scoped_mmap &) = delete;
  scoped_mmap &operator=(const scoped_mmap &) = delete;

  explicit scoped_mmap(void *addr, size_t len, int prot, int flags, int fd, uint64_t off);
  ~scoped_mmap() noexcept(false); /* throws if failed to unmap memory */

  [[clang::always_inline]] bool failed(void) const {
    return !ptr || unlikely(ptr == MAP_FAILED);
  }

  [[clang::always_inline]] explicit operator bool(void) const {
    return !failed();
  }
};

}
