#pragma once
#include "assert.h"
#include "likely.h"
#include "eintr.h"

#include <utility>

#include <unistd.h>

namespace jove {

namespace robust {
int close(int fd);
}

class scoped_fd {
  int fd = -1;

public:
  scoped_fd() noexcept = default;
  explicit scoped_fd(int fd) noexcept : fd(fd) {}
  explicit scoped_fd(scoped_fd &&other) noexcept : fd(other.fd) {
    other.fd = -1;
  }

  scoped_fd &operator=(scoped_fd &&other) noexcept {
    if (this == &other)
      return *this;

    close();
    std::swap(fd, other.fd);

    return *this;
  }

  scoped_fd &operator=(int fd_) noexcept {
    close();
    fd = fd_;
    return *this;
  }

  scoped_fd(const scoped_fd &) = delete;
  scoped_fd &operator=(const scoped_fd &) = delete;

  ~scoped_fd() noexcept { close(); }

  [[clang::always_inline]] explicit operator bool(void) const noexcept {
    return likely(fd >= 0);
  }

  [[clang::always_inline]] int get(void) const noexcept(false) {
    const int res = this->fd;
    aassert(res >= 0);
    __builtin_assume(res >= 0);
    return res;
  }

  [[clang::always_inline]] void close(void) noexcept {
    if (*this) {
      //
      // "Retrying the close() after a failure return is the wrong thing to do,
      // since this may cause a reused file descriptor from another thread to be
      // closed." - close(2)
      //
      (void)robust::close(fd);

      fd = -1; /* reset */
    }
  }

  std::string readlink_path(void) const noexcept(false);
};

}
