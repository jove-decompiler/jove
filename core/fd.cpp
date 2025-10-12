#include "fd.h"
#include "util.h"
#include "likely.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <memory>

#include <fcntl.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>

namespace jove {

template <bool IsRead>
static ssize_t robust_read_or_write(int fd, void *const buf, const size_t count) {
  static constexpr unsigned sysno = IsRead ? SYS_read : SYS_write;

  uint8_t *const _buf = (uint8_t *)buf;

  unsigned n = 0;
  do {
    unsigned left = count - n;

    ssize_t ret = ::syscall(sysno, fd, &_buf[n], left);
    if (unlikely(ret == 0))
      return -EIO;

    if (unlikely(ret < 0)) {
      int err = errno;

      if (err == EINTR)
        continue;

      return -err;
    }

    n += ret;
  } while (n != count);

  return n;
}

ssize_t robust_read(int fd, void *const buf, const size_t count) {
  return robust_read_or_write<true /* r */>(fd, buf, count);
}

ssize_t robust_write(int fd, const void *const buf, const size_t count) {
  return robust_read_or_write<false /* w */>(fd, const_cast<void *>(buf), count);
}

ssize_t robust_copy_file_range(int in_fd, off_t *in_off, int out_fd,
                               off_t *out_off, size_t len) {
  const size_t saved_len = len;

  do {
    ssize_t ret = ::copy_file_range(in_fd, in_off, out_fd, out_off, len, 0);

    if (unlikely(ret == 0))
      return -EIO;

    if (unlikely(ret < 0)) {
      int err = errno;
      if (err == EINTR)
        continue;

      return -err;
    }

    len -= ret;
  } while (len != 0);

  return saved_len;
}

ssize_t robust_sendfile_from_fd(int out_fd, int in_fd, off_t *in_off, size_t file_size) {
  const size_t saved_file_size = file_size;

  do {
    ssize_t ret = ::sendfile(out_fd, in_fd, in_off, file_size);

    if (unlikely(ret == 0))
      return -EIO;

    if (unlikely(ret < 0)) {
      int err = errno;
      if (err == EINTR)
        continue;

      return -err;
    }

    file_size -= ret;
  } while (file_size != 0);

  return saved_file_size;
}

ssize_t robust_sendfile(int fd, const char *file_path, size_t file_size) {
  scoped_fd in_fd(::open(file_path, O_RDONLY));
  if (!in_fd)
    throw std::runtime_error(std::string("robust_sendfile: open failed: ") +
                             strerror(errno));
  return robust_sendfile_from_fd(fd, in_fd.get(), nullptr, file_size);
}

ssize_t robust_sendfile_with_size(int fd, const char *file_path) {
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

ssize_t robust_receive_file_with_size(int fd, const char *out, unsigned file_perm) {
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

    file_size = std::strtoul(file_size_str.c_str(), nullptr, 10);
  }

  if (unlikely(!file_size))
    throw std::runtime_error("robust_receive_file_with_size: !file_size");

  int pipefd[2];
  if (::pipe(pipefd) < 0)
    return -errno;

  scoped_fd rfd(pipefd[0]);
  scoped_fd wfd(pipefd[1]);

  scoped_fd out_fd(::open(out, O_WRONLY | O_TRUNC | O_CREAT, file_perm));
  if (!out_fd)
    return -errno;

  size_t remaining = file_size;
  const size_t SPLICE_CHUNK = 64 * 1024; // 64KB per splice
  while (remaining > 0) {
    size_t to_move = std::min(remaining, SPLICE_CHUNK);

    // socket → pipe
    ssize_t n = ::splice(fd, nullptr, wfd.get(), nullptr, to_move,
                         SPLICE_F_MOVE | SPLICE_F_MORE);
    if (n < 0)
      return -errno;

    if (n == 0)
      break;

    assert(n > 0);

    // pipe → file
    ssize_t m = ::splice(rfd.get(), nullptr, out_fd.get(), nullptr, n,
                         SPLICE_F_MOVE | SPLICE_F_MORE);
    if (m < 0)
      return -errno;

    if (m == 0)
      throw std::runtime_error("robust_receive_file_with_size: !m");

    assert(m > 0);
    remaining -= m;
  }

  if (remaining != 0)
    throw std::runtime_error("robust_receive_file_with_size: remaining > 0");

  return file_size;
}

std::string scoped_fd::readlink_path(void) const noexcept(false) {
  std::string res;
  res.resize(2 * PATH_MAX);

  std::string proc_path = "/proc/self/fd/" + std::to_string(this->get());

  ssize_t len = ::readlink(proc_path.c_str(), &res[0], res.size() - 1);
  if (len < 0) {
    int err = errno;
    throw std::runtime_error("readlink() failed: " + std::string(strerror(err)));
  }

  assert(len < res.size());
  res.resize(len);

  return res;
}

}
