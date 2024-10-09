#pragma once
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <unistd.h>
#include <sys/sendfile.h>

#include <cstddef>
#include <cassert>
#include <cstdint>

namespace jove {

ssize_t robust_read(int fd, void *const buf, const size_t count);
ssize_t robust_write(int fd, const void *const buf, const size_t count);
ssize_t robust_sendfile_from_fd(int out_fd, int in_fd, off_t *in_off, size_t file_size);
ssize_t robust_sendfile(int fd, const char *file_path, size_t file_size);
ssize_t robust_sendfile_with_size(int fd, const char *file_path);
ssize_t robust_receive_file_with_size(int fd, const char *out, unsigned file_perm);
ssize_t robust_copy_file_range(int in_fd, off_t *in_off, int out_fd,
                               off_t *out_off, size_t len);

struct scoped_fd {
  const int fd;

  scoped_fd() = delete;
  scoped_fd(const scoped_fd &) = delete;
  scoped_fd &operator=(const scoped_fd &) = delete;

  explicit scoped_fd(int fd) : fd(fd) {}
  ~scoped_fd() noexcept(false); /* throws if failed to close file descriptor */

  int get(void) const {
    assert(fd >= 0);
    return fd;
  }

  operator bool(void) const { return fd >= 0; }
};

}
