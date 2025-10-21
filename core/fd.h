#pragma once
#include "assert.h"
#include "likely.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <utility>

#include <unistd.h>
#include <sys/sendfile.h>

namespace jove {

ssize_t robust_read(int fd, void *const buf, const size_t count);
ssize_t robust_write(int fd, const void *const buf, const size_t count);
ssize_t robust_sendfile_from_fd(int out_fd, int in_fd, off_t *in_off, size_t file_size);
ssize_t robust_sendfile(int fd, const char *file_path, size_t file_size);
ssize_t robust_sendfile_with_size(int fd, const char *file_path);
ssize_t robust_receive_file_with_size(int fd, const char *out, unsigned file_perm);
ssize_t robust_copy_file_range(int in_fd, off_t *in_off, int out_fd,
                               off_t *out_off, size_t len);

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

  [[clang::always_inline]] bool valid(void) const noexcept {
    return likely(fd >= 0);
  }

  [[clang::always_inline]] explicit operator bool(void) const noexcept {
    return valid();
  }

  [[clang::always_inline]] int get(void) const noexcept(false) {
    const int res = fd;
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
      (void)::close(fd);

      fd = -1; /* reset */
    }
  }

  std::string readlink_path(void) const noexcept(false);
};

}
