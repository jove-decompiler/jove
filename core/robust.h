#pragma once
#include <cstddef>

#include <sys/sendfile.h>

namespace jove {
namespace robust {

int close(int fd);
int dup2(int fd, int newfd);

ssize_t read(int fd, void *const buf, const size_t count);
ssize_t write(int fd, const void *const buf, const size_t count);
ssize_t sendfile_from_fd(int out_fd, int in_fd, off_t *in_off, size_t file_size);
ssize_t sendfile(int fd, const char *file_path, size_t file_size);
ssize_t sendfile_with_size(int fd, const char *file_path);
ssize_t receive_file_with_size(int fd, const char *out, unsigned file_perm);
ssize_t copy_file_range(int in_fd, off_t *in_off, int out_fd, off_t *out_off, size_t len);

}
}
