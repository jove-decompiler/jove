#include "robust.h"
#include "sys.h" /* (async-signal-safe) */
#include "likely.h"
#include "eintr.h"
#include "fd.h"
#include "util.h"
#include "sizes.h"

#include <cerrno>
#include <cstring>
#include <climits>

#include <fcntl.h>

namespace jove {
namespace robust {

int close(int fd) { return sys::retry_eintr(::close, fd); }
int dup2(int fd, int newfd) { return sys::retry_eintr(::dup2, fd, newfd); }

template <bool IsRead>
static ssize_t read_or_write(int fd, void *buf, size_t count) {
  if (count == 0)
    return 0;
  __builtin_assume(count > 0);
  if (count > static_cast<size_t>(SSIZE_MAX))
    return -EOVERFLOW;

  auto *p = static_cast<unsigned char *>(buf);
  size_t n = 0;
  while (n != count) {
    size_t left  = count - n;
    size_t chunk = left > static_cast<size_t>(SSIZE_MAX)
                        ? static_cast<size_t>(SSIZE_MAX)
                        : left;

    const ssize_t ret = IsRead
      ? _jove_sys_read (fd, reinterpret_cast<char*>(p + n), chunk)
      : _jove_sys_write(fd, reinterpret_cast<char*>(p + n), chunk);

    if (ret > 0) {
      n += static_cast<size_t>(ret);
      continue;
    }

    if (ret == -EINTR || ret == -EAGAIN)
      continue;

    if (ret == 0)
      return -EPIPE;

    aassert(ret < 0);
    return ret;

  }

  return static_cast<ssize_t>(n);
}

ssize_t read(int fd, void *const buf, const size_t count) {
  return robust::read_or_write<true /* r */>(fd, buf, count);
}

ssize_t write(int fd, const void *const buf, const size_t count) {
  return robust::read_or_write<false /* w */>(fd, const_cast<void *>(buf), count);
}

ssize_t copy_file_range(int in_fd, off_t *in_off, int out_fd, off_t *out_off, size_t len) {
  const size_t saved_len = len;

  do {
    ssize_t ret = sys::retry_eintr(::copy_file_range, in_fd, in_off, out_fd, out_off, len, 0);
    if (unlikely(ret == 0))
      return -EIO;

    if (unlikely(ret < 0))
      return -errno;

    __builtin_assume(ret > 0);

    len -= ret;
  } while (len != 0);

  return saved_len;
}

ssize_t sendfile_from_fd(int out_fd, int in_fd, off_t *in_off, size_t file_size) {
  const size_t saved_file_size = file_size;

  do {
    ssize_t ret = sys::retry_eintr(::sendfile, out_fd, in_fd, in_off, file_size);

    if (unlikely(ret == 0))
      return -EIO;

    if (unlikely(ret < 0))
      return -errno;

    __builtin_assume(ret > 0);

    file_size -= ret;
  } while (file_size != 0);

  return saved_file_size;
}

ssize_t sendfile(int fd, const char *file_path, size_t file_size) {
  scoped_fd in_fd(::open(file_path, O_RDONLY));
  if (!in_fd)
    throw std::runtime_error(std::string("robust::sendfile: open failed: ") +
                             strerror(errno));
  return robust::sendfile_from_fd(fd, in_fd.get(), nullptr, file_size);
}

ssize_t sendfile_with_size(int fd, const char *file_path) {
  ssize_t ret;

  uint64_t file_size = size_of_file(file_path);

  std::string file_size_str = std::to_string(file_size);

  ret = robust::write(fd, file_size_str.c_str(), file_size_str.size() + 1);
  if (ret < 0)
    return ret;

  ret = robust::sendfile(fd, file_path, file_size);
  if (ret < 0)
    return ret;

  return file_size;
}

ssize_t receive_file_with_size(int fd, const char *out, unsigned file_perm) {
  const size_t file_size = ({
    std::string s;
    for (;;) {
      unsigned char ch;
      ssize_t n = robust::read(fd, &ch, 1);
      if (n < 0)
        return n;
      if (n == 0)
        return -EPIPE;
      aassert(n == 1);
      if (ch == '\0')
        break;
      s.push_back(static_cast<char>(ch));
      if (s.size() > 32)
        return -EINVAL;
    }

    char *end = nullptr;
    errno = 0;
    unsigned long long v = std::strtoull(s.c_str(), &end, 10);
    if (errno == ERANGE || end == s.c_str() || *end != '\0')
      return -EINVAL;

    const size_t len = static_cast<uint64_t>(v);
    if (len > static_cast<uint64_t>(SSIZE_MAX))
      return -EOVERFLOW;

    len;
  });

  int pipefd[2];
  if (::pipe2(pipefd, O_CLOEXEC) < 0)
    return -errno;

  scoped_fd rfd(pipefd[0]);
  scoped_fd wfd(pipefd[1]);

  scoped_fd out_fd(::open(
      out, O_WRONLY | O_TRUNC | O_CREAT | O_LARGEFILE | O_CLOEXEC, file_perm));
  if (!out_fd)
    return -errno;

  constexpr size_t SPLICE_CHUNK = 1 * MiB;

  uint64_t remaining = file_size;
  while (remaining > 0) {
    // socket → pipe
    ssize_t n;
    for (;;) {
      const size_t to_move =
          static_cast<size_t>(std::min<uint64_t>(remaining, SPLICE_CHUNK));

      n = ::splice(fd, nullptr, wfd.get(), nullptr, to_move,
                   SPLICE_F_MOVE | SPLICE_F_MORE);
      if (n > 0)
        break;
      if (n == 0)
        return -EPIPE;
      int err = errno;
      if (err == EINTR || err == EAGAIN)
        continue;
      return -err;
    }

    // pipe → file (drain exactly 'n' bytes)
    ssize_t left = n;
    while (left > 0) {
      for (;;) {
        const ssize_t m = ::splice(rfd.get(), nullptr,
                                   out_fd.get(), nullptr,
                                   left, SPLICE_F_MOVE);
        if (m > 0) {
          left -= m;
          remaining -= m;
          break;
        }

        int err = errno;
        if (err == EINTR || err == EAGAIN)
          continue;

        if (err == EIO || err == EOPNOTSUPP || err == EINVAL || err == ENOSYS) {
          //
          // fallback
          //
          std::vector<uint8_t> buf;
          buf.resize(left);

          ssize_t rd = robust::read(rfd.get(), &buf[0], left);
          if (rd < 0)
            return rd;
          aassert(rd == left);

          ssize_t wr = robust::write(out_fd.get(), &buf[0], rd);
          if (wr < 0)
            return wr;
          aassert(wr == left);

          aassert(wr == rd);

          remaining -= left;
          left = 0;
          break;
        }

        return -err;
      }
    }
  }

  return static_cast<ssize_t>(file_size);
}

}
}
