#pragma once
#include <cstddef>
#include <cassert>

namespace jove {

long robust_read(int fd, void *const buf, const size_t count);
long robust_write(int fd, const void *const buf, const size_t count);
long robust_sendfile_from_fd(int out_fd, int in_fd, size_t file_size);
long robust_sendfile(int fd, const char *file_path, size_t file_size);
long robust_sendfile_with_size(int fd, const char *file_path);
long robust_receive_file_with_size(int fd, const char *out, unsigned file_perm);

struct scoped_fd {
  const int fd;

  scoped_fd(int fd) : fd(fd) {}
  ~scoped_fd() noexcept(false); /* throws if failed to close file descriptor */

  int get(void) const {
    assert(fd >= 0);
    return fd;
  }

  operator bool(void) const { return fd >= 0; }
};

}
