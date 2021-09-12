static _INL void *_memcpy(void *dest, const void *src, size_t n) {
  unsigned char *d = dest;
  const unsigned char *s = src;

  for (; n; n--)
    *d++ = *s++;

  return dest;
}

static _INL void *_memset(void *dst, int c, size_t n) {
  if (n != 0) {
    unsigned char *d = dst;

    do
      *d++ = (unsigned char)c;
    while (--n != 0);
  }
  return (dst);
}

static _INL void *_memchr(const void *s, int c, size_t n) {
  if (n != 0) {
    const unsigned char *p = s;

    do {
      if (*p++ == (unsigned char)c)
        return ((void *)(p - 1));
    } while (--n != 0);
  }
  return (NULL);
}

static _INL size_t _strlen(const char *str) {
  const char *s;

  for (s = str; *s; ++s)
    ;
  return (s - str);
}

static _INL char *_strcat(char *s, const char *append) {
  char *save = s;

  for (; *s; ++s)
    ;
  while ((*s++ = *append++) != '\0')
    ;
  return (save);
}

static _INL void _uint_to_string(uint64_t x, char *Str, unsigned Radix) {
  // First, check for a zero value and just short circuit the logic below.
  if (x == 0) {
    *Str++ = '0';

    // null-terminate
    *Str = '\0';
    return;
  }

  static const char Digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";

  char Buffer[65];
  char *BufPtr = &Buffer[sizeof(Buffer)];

  uint32_t N = x;

  while (N) {
    *--BufPtr = Digits[N % Radix];
    N /= Radix;
  }

  for (char *p = BufPtr; p != &Buffer[sizeof(Buffer)]; ++p)
    *Str++ = *p;

  // null-terminate
  *Str = '\0';
}

static _INL unsigned _read_pseudo_file(const char *path, char *out, size_t len) {
  unsigned n;

  {
#ifdef __aarch64__
    int fd = _jove_sys_openat(-1, path, O_RDONLY, S_IRWXU);
#else
    int fd = _jove_sys_open(path, O_RDONLY, S_IRWXU);
#endif
    if (fd < 0)
      _UNREACHABLE("could not open file from procfs. is it mounted?");

    // let n denote the number of characters read
    n = 0;

    for (;;) {
      ssize_t ret = _jove_sys_read(fd, &out[n], len - n);

      if (ret == 0)
        break;

      if (ret < 0) {
        if (ret == -EINTR)
          continue;

        _UNREACHABLE();
      }

      n += ret;
    }

    if (_jove_sys_close(fd) < 0)
      _UNREACHABLE();
  }

  return n;
}

static _INL unsigned _getHexDigit(char cdigit) {
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

static _INL uint64_t _u64ofhexstr(char *str_begin, char *str_end) {
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

static _INL void _description_of_address_for_maps(char *out, uintptr_t Addr, char *maps, const unsigned n) {
  out[0] = '\0'; /* empty */

  char *const beg = &maps[0];
  char *const end = &maps[n];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    {
      unsigned left = n - (line - beg);

      //
      // find the end of the current line
      //
      eol = _memchr(line, '\n', left);
    }

    unsigned left = eol - line;

    struct {
      uint64_t min, max;
    } vm;

    {
      char *dash = _memchr(line, '-', left);
      vm.min = _u64ofhexstr(line, dash);

      char *space = _memchr(line, ' ', left);
      vm.max = _u64ofhexstr(dash + 1, space);
    }

    //
    // does the given address exist within this mapping?
    //
    if (Addr >= vm.min && Addr < vm.max) {
      //
      // we have a match. If this mapping has a file path, we'll make it the
      // description
      //
      char *fwdslash = _memchr(line, '/', left);
      char *leftsqbr = _memchr(line, '[', left);

      if (fwdslash) {
        *eol = '\0';
        _strcat(out, fwdslash);
        *eol = '\n';
      } else if (leftsqbr) {
        *eol = '\0';
        _strcat(out, leftsqbr);
        *eol = '\n';
      } else {
        *out = '\0';
        return;
      }

      _strcat(out, "+0x");

      ssize_t Offset = Addr - vm.min;
      char offsetStr[65];
      _uint_to_string(Offset, offsetStr, 0x10);

      _strcat(out, offsetStr);

      return;
    }
  }
}

static _INL uintptr_t _parse_stack_end_of_maps(char *maps, const unsigned n) {
  char *const beg = &maps[0];
  char *const end = &maps[n];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    unsigned left = n - (line - beg);

    //
    // find the end of the current line
    //
    eol = _memchr(line, '\n', left);

    //
    // second hex address
    //
    if (eol[-1] == ']' &&
        eol[-2] == 'k' &&
        eol[-3] == 'c' &&
        eol[-4] == 'a' &&
        eol[-5] == 't' &&
        eol[-6] == 's' &&
        eol[-7] == '[') {
      char *dash = _memchr(line, '-', left);

      char *space = _memchr(line, ' ', left);
      uint64_t max = _u64ofhexstr(dash + 1, space);
      return max;
    }
  }

  _UNREACHABLE();
}

static _INL size_t _sum_iovec_lengths(const struct iovec *iov, unsigned n) {
  size_t expected = 0;
  for (unsigned i = 0; i < n; ++i)
    expected += iov[i].iov_len;
  return expected;
}

static _INL ssize_t _robust_write(int fd, void *const buf, const size_t count) {
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
