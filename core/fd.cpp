#include "fd.h"
#include "util.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#include <fcntl.h>
#include <unistd.h>
#include <sys/sendfile.h>

namespace jove {

template <bool IsRead>
static ssize_t robust_read_or_write(int fd, void *const buf, const size_t count) {
  uint8_t *const _buf = (uint8_t *)buf;

  unsigned n = 0;
  do {
    unsigned left = count - n;

    ssize_t ret = IsRead ? ::read(fd, &_buf[n], left) :
                          ::write(fd, &_buf[n], left);

    if (ret == 0)
      return -EIO;

    if (ret < 0) {
      int err = errno;

      if (err == EINTR)
        continue;

      return -err;
    }

    n += ret;
  } while (n != count);

  return n;
}

long robust_read(int fd, void *const buf, const size_t count) {
  return robust_read_or_write<true /* r */>(fd, buf, count);
}

long robust_write(int fd, const void *const buf, const size_t count) {
  return robust_read_or_write<false /* w */>(fd, const_cast<void *>(buf), count);
}

long robust_sendfile_from_fd(int out_fd, int in_fd, size_t file_size) {
  const size_t saved_file_size = file_size;

  do {
    ssize_t ret = ::sendfile(out_fd, in_fd, nullptr, file_size);

    if (ret == 0)
      return -EIO;

    if (ret < 0)
      return -errno;

    file_size -= ret;
  } while (file_size != 0);

  return saved_file_size;
}

long robust_sendfile(int fd, const char *file_path, size_t file_size) {
  scoped_fd in_fd = ::open(file_path, O_RDONLY);
  if (!in_fd)
    throw std::runtime_error(std::string("robust_sendfile: open failed: ") +
                             strerror(errno));
  return robust_sendfile_from_fd(fd, in_fd, file_size);
}

long robust_sendfile_with_size(int fd, const char *file_path) {
  ssize_t ret;

  uint32_t file_size = size_of_file32(file_path);

  std::string file_size_str = std::to_string(file_size);

  ret = robust_write(fd, file_size_str.c_str(), file_size_str.size() + 1);
  if (ret < 0)
    return ret;

  ret = robust_sendfile(fd, file_path, file_size);
  if (ret < 0)
    return ret;

  return file_size;
}

long robust_receive_file_with_size(int fd, const char *out, unsigned file_perm) {
  uint32_t file_size;
  {
    std::string file_size_str;

    char ch;
    do {
      ssize_t n = robust_read(fd, &ch, sizeof(char));
      if (n < 0)
        return n;

      assert(n == sizeof(char));

      file_size_str.push_back(ch);
    } while (ch != '\0');

    file_size = std::atoi(file_size_str.c_str());
  }
  assert(file_size > 0);

  std::vector<uint8_t> buff;
  buff.resize(file_size);

  {
    ssize_t res = robust_read(fd, &buff[0], buff.size());
    if (res < 0)
      return res;
  }

  ssize_t res = -EBADF;
  {
    scoped_fd fd = ::open(out, O_WRONLY | O_TRUNC | O_CREAT, file_perm);
    if (!fd)
      return -errno;

    res = robust_write(fd.get(), &buff[0], buff.size());
    if (res < 0)
      return res;
  }

  return res;
}

scoped_fd::~scoped_fd() noexcept(false) {
  if (fd < 0)
    return;

  if (::close(fd) < 0)
    throw std::runtime_error(std::string("scoped_fd: failed to close fd: ") +
                             strerror(errno));
}

}
