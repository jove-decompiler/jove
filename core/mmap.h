#pragma once
#include <cstdint>
#include <cstddef>

namespace jove {

struct scoped_mmap {
  const size_t len;
  void *const ptr;

  scoped_mmap() = delete;
  scoped_mmap(const scoped_mmap &) = delete;
  scoped_mmap &operator=(const scoped_mmap &) = delete;

  explicit scoped_mmap(void *addr, size_t len, int prot, int flags, int fd, uint64_t off);
  ~scoped_mmap() noexcept(false); /* throws if failed to unmap memory */

  bool failed(void) const; /* is ptr equal to MAP_FAILED */

  explicit operator bool(void) const { return !failed(); }
};

}
