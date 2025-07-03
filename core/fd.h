#pragma once
#include <unistd.h>
#include <sys/sendfile.h>

#include <cstddef>
#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <cstring> /* strerror */

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
  scoped_fd() = delete;
  scoped_fd(const scoped_fd &) = delete;
  scoped_fd &operator=(const scoped_fd &) = delete;

  explicit scoped_fd(int fd) noexcept : fd(fd) {}
  explicit scoped_fd(scoped_fd &&other) noexcept : fd(other.fd) {
    other.fd = -1;
  }

  scoped_fd &operator=(scoped_fd &&other) noexcept(false) {
    if (this != &other) {
      close();

      fd = other.fd;
      other.fd = -1;
    }
    return *this;
  }

  ~scoped_fd() noexcept(false) { /* throws if fails to close valid fd */
    close();
  }

  explicit operator bool(void) const { return fd >= 0; }

  int get(void) const {
    assert(*this);
    return fd;
  }

  void close(void) noexcept(false) {
    if (*this) {
      if (::close(fd) < 0)
        throw std::runtime_error(
            std::string("scoped_fd: failed to close fd: ") + strerror(errno));

      fd = -1;
    }
  }
};

}
