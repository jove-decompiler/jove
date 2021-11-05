static _INL _UNUSED void *_memcpy(void *dest, const void *src, size_t n) {
  unsigned char *d = dest;
  const unsigned char *s = src;

  for (; n; n--)
    *d++ = *s++;

  return dest;
}

static _INL _UNUSED void *_memset(void *dst, int c, size_t n) {
  if (n != 0) {
    unsigned char *d = dst;

    do
      *d++ = (unsigned char)c;
    while (--n != 0);
  }
  return (dst);
}

static _INL _UNUSED void *_memchr(const void *s, int c, size_t n) {
  if (n != 0) {
    const unsigned char *p = s;

    do {
      if (*p++ == (unsigned char)c)
        return ((void *)(p - 1));
    } while (--n != 0);
  }
  return (NULL);
}

static _INL _UNUSED size_t _strlen(const char *str) {
  const char *s;

  for (s = str; *s; ++s)
    ;
  return (s - str);
}

static _INL _UNUSED char *_strcat(char *s, const char *append) {
  char *save = s;

  for (; *s; ++s)
    ;
  while ((*s++ = *append++) != '\0')
    ;
  return (save);
}

static _INL _UNUSED void _uint_to_string(uint64_t x, char *Str, unsigned Radix) {
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

  uint64_t N = x;

  while (N) {
    *--BufPtr = Digits[N % Radix];
    N /= Radix;
  }

  for (char *p = BufPtr; p != &Buffer[sizeof(Buffer)]; ++p)
    *Str++ = *p;

  // null-terminate
  *Str = '\0';
}

static _UNUSED unsigned _read_pseudo_file(const char *path, char *out, size_t len) {
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

static _UNUSED unsigned _getHexDigit(char cdigit) {
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

static _UNUSED uint64_t _u64ofhexstr(char *str_begin, char *str_end) {
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

static _UNUSED void _description_of_address_for_maps(char *out, uintptr_t Addr, char *maps, const unsigned n) {
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

static _UNUSED uintptr_t _parse_stack_end_of_maps(char *maps, const unsigned n) {
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

static _INL _UNUSED uintptr_t _get_stack_end(void) {
  char buff[4096 * 16];
  unsigned n = _read_pseudo_file("/proc/self/maps", buff, sizeof(buff));
  buff[n] = '\0';

  uintptr_t res = _parse_stack_end_of_maps(buff, n);
  return res;
}

static _INL _UNUSED size_t _sum_iovec_lengths(const struct iovec *iov, unsigned n) {
  size_t expected = 0;
  for (unsigned i = 0; i < n; ++i)
    expected += iov[i].iov_len;
  return expected;
}

static _UNUSED ssize_t _robust_write(int fd, void *const buf, const size_t count) {
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

static _UNUSED bool _should_sleep_on_crash(char *envs, const unsigned n) {
  char *const beg = &envs[0];
  char *const end = &envs[n];

  char *eoe;
  for (char *env = beg; env != end; env = eoe + 1) {
    unsigned left = n - (env - beg);

    //
    // find the end of the current entry
    //
    eoe = _memchr(env, '\0', left);

    if (env[0] == 'J' &&
        env[1] == 'O' &&
        env[2] == 'V' &&
        env[3] == 'E' &&
        env[4] == '_' &&
        env[5] == 'S' &&
        env[6] == 'L' &&
        env[7] == 'E' &&
        env[8] == 'E' &&
        env[9] == 'P' &&
        env[10] == '_' &&
        env[11] == 'O' &&
        env[12] == 'N' &&
        env[13] == '_' &&
        env[14] == 'C' &&
        env[15] == 'R' &&
        env[16] == 'A' &&
        env[17] == 'S' &&
        env[18] == 'H' &&
        env[19] == '=') {
      return true;
    }
  }

  return false;
}

static _UNUSED bool _jove_is_readable_mem(uintptr_t Addr) {
  pid_t pid;
  {
    long ret = _jove_sys_getpid();
    if (unlikely(ret < 0))
      _UNREACHABLE();

    pid = ret;
  }

  struct iovec lvec[1];
  struct iovec rvec[1];

  uint8_t byte;

  lvec[0].iov_base = &byte;
  lvec[0].iov_len = sizeof(byte);

  rvec[0].iov_base = (void *)Addr;
  rvec[0].iov_len = sizeof(byte);

  long ret = _jove_sys_process_vm_readv(pid,
                                        lvec, ARRAY_SIZE(lvec),
                                        rvec, ARRAY_SIZE(rvec),
                                        0);

  return ret == sizeof(byte);
}

static uintptr_t _mmap_rw_anonymous_private_memory(size_t len);

uintptr_t _jove_alloc_stack(void) {
  unsigned long ret = _mmap_rw_anonymous_private_memory(JOVE_STACK_SIZE);
  if (IS_ERR_VALUE(ret))
    _UNREACHABLE("failed to allocate stack");

  //
  // create guard pages on both sides
  //
  unsigned long beg = ret;
  unsigned long end = beg + JOVE_STACK_SIZE;

  if (_jove_sys_mprotect(beg, JOVE_PAGE_SIZE, PROT_NONE) < 0)
    _UNREACHABLE("failed to create guard page #1");

  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0)
    _UNREACHABLE("failed to create guard page #2");

  return beg;
}

void _jove_free_stack(uintptr_t beg) {
  if (_jove_sys_munmap(beg, JOVE_STACK_SIZE) < 0)
    _UNREACHABLE("failed to deallocate stack");
}

uintptr_t _jove_alloc_callstack(void) {
  long ret = _mmap_rw_anonymous_private_memory(JOVE_CALLSTACK_SIZE);
  if (ret < 0 && ret > -4096)
    _UNREACHABLE("failed to allocate callstack");

  unsigned long uret = (unsigned long)ret;

  //
  // create guard pages on both sides
  //
  unsigned long beg = uret;
  unsigned long end = beg + JOVE_CALLSTACK_SIZE;

  if (_jove_sys_mprotect(beg, JOVE_PAGE_SIZE, PROT_NONE) < 0)
    _UNREACHABLE("failed to create guard page #1");

  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0)
    _UNREACHABLE("failed to create guard page #2");

  return beg;
}

void _jove_free_callstack(uintptr_t start) {
  if (_jove_sys_munmap(start - JOVE_PAGE_SIZE, JOVE_CALLSTACK_SIZE) < 0)
    _UNREACHABLE("failed to deallocate callstack");
}
