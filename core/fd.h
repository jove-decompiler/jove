#pragma once
#include <cstddef>
#include <cassert>

namespace jove {

long robust_read(int fd, void *const buf, const size_t count);
long robust_write(int fd, const void *const buf, const size_t count);
long robust_sendfile(int socket, const char *file_path, size_t file_size);
long robust_sendfile_with_size(int socket, const char *file_path);
long robust_receive_file_with_size(int socket, const char *out, unsigned file_perm);

class scoped_fd {
  int fd = -1;

public:
  scoped_fd(int fd) : fd(fd) {}
  ~scoped_fd();

  int get(void) {
    assert(fd >= 0);

    return fd;
  }
};

}
