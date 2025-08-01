#include "mmap.h"

#include <stdexcept>
#include <cstring>

namespace jove {

scoped_mmap::scoped_mmap(void *addr, size_t len, int prot, int flags, int fd,
                         uint64_t off)
    : len(len), ptr(::mmap(addr, len, prot, flags, fd, off)) {}

scoped_mmap::~scoped_mmap() noexcept(false) {
  if (failed())
    return;

  if (::munmap(ptr, len) < 0)
    throw std::runtime_error(std::string("scoped_mmap: munmap failed: ") +
                             strerror(errno));
}

}
