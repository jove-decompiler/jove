#pragma once
#include "assert.h"

#include <cstdint>
#include <cstddef>

#include <sys/mman.h>

namespace jove {

struct scoped_mmap {
  const size_t len = ~size_t(0);
  void *const ptr = nullptr;

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
};

}
