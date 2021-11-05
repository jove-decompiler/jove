#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#define _INL     __attribute__((always_inline))
#define _NOINL   __attribute__((noinline))
#define _NORET   __attribute__((noreturn))
#define _UNUSED  __attribute__((unused))
#define _HIDDEN  __attribute__((visibility("hidden")))

#define JOVE_SYS_ATTR _NOINL _HIDDEN _UNUSED
#include "jove_sys.h"

typedef struct {
  void *ptr;
  unsigned len;
} vdso_description_t;

//
// utility functions
//
static vdso_description_t GetVDSO(void);
static ssize_t robust_write(int fd, void *const buf, const size_t count);

_NORET _HIDDEN void _start(void) {
  vdso_description_t vdso = GetVDSO();
  if (robust_write(STDOUT_FILENO, vdso.ptr, vdso.len) == vdso.len)
    _jove_sys_exit_group(0);
  else
    _jove_sys_exit_group(1);

  __builtin_trap();
  __builtin_unreachable();
}

static vdso_description_t _parse_vdso_info(char *maps, const unsigned n);
static _INL unsigned _read_pseudo_file(const char *path, char *out, size_t len);

vdso_description_t GetVDSO(void) {
  char buff[4096 * 16];
  unsigned n = _read_pseudo_file("/proc/self/maps", buff, sizeof(buff));
  buff[n] = '\0';

  return _parse_vdso_info(buff, n);
}

static _INL uint64_t _u64ofhexstr(char *str_begin, char *str_end);
static _INL void *_memchr(const void *s, int c, size_t n);

vdso_description_t _parse_vdso_info(char *maps, const unsigned n) {
  vdso_description_t res;

  res.ptr = NULL;
  res.len = 0;

  char *const beg = &maps[0];
  char *const end = &maps[n];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    unsigned left = n - (line - beg);

    eol = _memchr(line, '\n', left);

    if (eol[-1] == ']' &&
        eol[-2] == 'o' &&
        eol[-3] == 's' &&
        eol[-4] == 'd' &&
        eol[-5] == 'v' &&
        eol[-6] == '[') {
      char *dash = _memchr(line, '-', left);
      char *space = _memchr(line, ' ', left);

      uint64_t min = _u64ofhexstr(line, dash);
      uint64_t max = _u64ofhexstr(dash+1, space);

      res.ptr = (void *)min;
      res.len = max - min;
    }
  }

  return res;
}

//
// utility functions
//
void *_memchr(const void *s, int c, size_t n) {
  if (n != 0) {
    const unsigned char *p = s;

    do {
      if (*p++ == (unsigned char)c)
        return ((void *)(p - 1));
    } while (--n != 0);
  }
  return (NULL);
}

static unsigned _getHexDigit(char cdigit) {
  unsigned radix = 0x10;

  unsigned r;

  if (radix == 16 || radix == 36) {
    r = cdigit - '0';
    if (r <= 9)
      return r;

    r = cdigit - 'A';
    if (r <= radix - 11U)
      return r + 10;

    r = cdigit - 'a';
    if (r <= radix - 11U)
      return r + 10;

    radix = 10;
  }

  r = cdigit - '0';
  if (r < radix)
    return r;

  return -1U;
}

uint64_t _u64ofhexstr(char *str_begin, char *str_end) {
  const unsigned radix = 0x10;

  uint64_t res = 0;

  char *p = str_begin;
  size_t slen = str_end - str_begin;

  // Figure out if we can shift instead of multiply
  unsigned shift = (radix == 16 ? 4 : radix == 8 ? 3 : radix == 2 ? 1 : 0);

  // Enter digit traversal loop
  for (char *e = str_end; p != e; ++p) {
    unsigned digit = _getHexDigit(*p);

    if (!(digit < radix))
      return 0;

    // Shift or multiply the value by the radix
    if (slen > 1) {
      if (shift)
        res <<= shift;
      else
        res *= radix;
    }

    // Add in the digit we just interpreted
    res += digit;
  }

  return res;
}

unsigned _read_pseudo_file(const char *path, char *out, size_t len) {
  unsigned n;

  {
    int fd = _jove_sys_open(path, O_RDONLY, S_IRWXU);
    if (fd < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }

    // let n denote the number of characters read
    n = 0;

    for (;;) {
      ssize_t ret = _jove_sys_read(fd, &out[n], len - n);

      if (ret == 0)
        break;

      if (ret < 0) {
        if (ret == -EINTR)
          continue;

        __builtin_trap();
        __builtin_unreachable();
      }

      n += ret;
    }

    if (_jove_sys_close(fd) < 0) {
      __builtin_trap();
      __builtin_unreachable();
    }
  }

  return n;
}

ssize_t robust_write(int fd, void *const buf, const size_t count) {
  uint8_t *const _buf = (uint8_t *)buf;

  unsigned n = 0;
  do {
    unsigned left = count - n;

    ssize_t ret = _jove_sys_write(fd, &_buf[n], left);

    if (ret == 0)
      return -EIO;

    if (ret < 0) {
      if (ret == -EINTR)
        continue;

      return ret;
    }

    n += ret;
  } while (n != count);

  return n;
}
