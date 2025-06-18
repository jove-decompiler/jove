#pragma once

#include "jove.constants.h"
#include "jove.macros.h"
#include "jove.sys.h"

#include "jove.mutex.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <linux/limits.h> /* ARG_MAX and PATH_MAX */

#ifndef JOVE_TRACK_ALLOCATIONS
#define JOVE_TRACK_ALLOCATION(beg, len, desc) do {} while (false)
#define JOVE_UNTRACK_ALLOCATION(beg, len)     do {} while (false)
#endif

#include "jove.stdlib.c.inc"

//
// essential stuff
//

_NORET
static void _jove_on_crash(char mode) {
  switch (mode) {
  case 's': { /* sleep */
    for (;;)
      _jove_sleep();
    break;
  }

  case 'a': /* abort */
    _jove_sys_kill(_jove_sys_getpid(), SIGABRT);
    /* fallthrough */
  case '\0':
    _jove_sys_exit_group(0x77);
    __UNREACHABLE();
  case 'x':
    _jove_sys_exit_group(1);
    __UNREACHABLE();

  default: /* interpret as exit status */
    _jove_sys_exit_group((int)mode);
    __UNREACHABLE();
  }

  __UNREACHABLE();
}

static void _jove_pause(void) {
  char buff;
  while (_jove_sys_read(STDIN_FILENO, &buff, 1) > 0 && buff != '\n')
    ;
}

static _UNUSED ssize_t _jove_robust_write(int fd, const void *buf,
                                          size_t count);

static _UNUSED ssize_t _jove_robust_writev_trash(int fd, struct iovec *iov,
                                                 unsigned iov_cnt);

static _NOINL void _jove_dump_tid_and_str_with_len(const char *str,
                                                   unsigned len) {
  char buff[64];

  buff[0] = '[';
  char *chp = _uint_to_string(_jove_sys_gettid(), &buff[1], 10);
  *chp++ = ']';
  *chp++ = ' ';

  struct iovec __iov_arr[2] = {
      {.iov_base = &buff[0], .iov_len = chp - &buff[0]},
      {.iov_base = (str), .iov_len = (len)}};

  _jove_robust_writev_trash(JOVE_DUMP_FD, &__iov_arr[0], ARRAY_SIZE(__iov_arr));
}

static _NOINL void _jove_dump_str_with_len(const char *str, unsigned len) {
  _jove_robust_write(JOVE_DUMP_FD, str, len);
}

static _NOINL void _jove_dump_on_crash(const char *str, unsigned len) {
  _DUMP_WITH_LEN(str, len);
  _jove_on_crash(JOVE_CRASH_MODE);
  __UNREACHABLE();
}

static _UNUSED ssize_t _do_writev_readv(int fd, const struct iovec *iov,
                                       unsigned iov_cnt, bool do_writev) {
  ssize_t res;
  do {
    res = do_writev ? _jove_sys_writev(fd, iov, iov_cnt)
                    : _jove_sys_readv(fd, iov, iov_cnt);
  } while (res == -EINTR);
  return res;
}

static _UNUSED size_t _bytes_of_iov(const struct iovec *iov, unsigned iov_cnt) {
  size_t res = 0;
  for (unsigned i = 0; i < iov_cnt; ++i)
    res += iov[i].iov_len;
  return res;
}

ssize_t _jove_robust_write(int fd, const void *buf, size_t count) {
  ssize_t ret = 0;
  ssize_t total = 0;

  while (count) {
    ret = _jove_sys_write(fd, buf, count);
    if (unlikely(ret < 0)) {
      if (ret == -EINTR)
        continue;
      break;
    }

    if (unlikely(ret == 0))
      return -EIO;

    count -= ret;
    buf += ret;
    total += ret;
  }

  return total;
}

static _UNUSED ssize_t _jove_robust_writev_readv_trash(int fd,
                                                       struct iovec *iov,
                                                       unsigned iov_cnt,
                                                       bool do_writev) {
  size_t offset = 0;
  ssize_t total = 0;
  ssize_t ret;
  size_t orig_len, tail;
  unsigned niov;
  size_t bytes = _bytes_of_iov(iov, iov_cnt);

  if (bytes <= 0) {
    return 0;
  }

  offset = 0;

  while (bytes > 0) {
    /* Find the start position, skipping `offset' bytes:
     * first, skip all full-sized vector elements, */
    for (niov = 0; niov < iov_cnt && offset >= iov[niov].iov_len; ++niov) {
      offset -= iov[niov].iov_len;
    }

    /* niov == iov_cnt would only be valid if bytes == 0, which
     * we already ruled out in the loop condition.  */
    _ASSERT(niov < iov_cnt);
    iov += niov;
    iov_cnt -= niov;

    if (offset) {
      /* second, skip `offset' bytes from the (now) first element,
       * undo it on exit */
      iov[0].iov_base += offset;
      iov[0].iov_len -= offset;
    }
    /* Find the end position skipping `bytes' bytes: */
    /* first, skip all full-sized elements */
    tail = bytes;
    for (niov = 0; niov < iov_cnt && iov[niov].iov_len <= tail; ++niov) {
      tail -= iov[niov].iov_len;
    }
    if (tail) {
      /* second, fixup the last element, and remember the original
       * length */
      _ASSERT(niov < iov_cnt);
      _ASSERT(iov[niov].iov_len > tail);
      orig_len = iov[niov].iov_len;
      iov[niov++].iov_len = tail;
      ret = _do_writev_readv(fd, iov, niov, do_writev);
      /* Undo the changes above before checking for errors */
      iov[niov - 1].iov_len = orig_len;
    } else {
      ret = _do_writev_readv(fd, iov, niov, do_writev);
    }
    if (offset) {
      iov[0].iov_base -= offset;
      iov[0].iov_len += offset;
    }

    if (ret < 0) {
      int err = -ret;
      _ASSERT(err != EINTR);
      if (err == EAGAIN && total > 0) {
        return total;
      }
      return -1;
    }

    if (ret == 0 && !do_writev) {
      /* read returns 0 on EOF */
      break;
    }

    /* Prepare for the next iteration */
    offset += ret;
    total += ret;
    bytes -= ret;
  }

  return total;
}

ssize_t _jove_robust_writev_trash(int fd, struct iovec *iov, unsigned iov_cnt) {
  return _jove_robust_writev_readv_trash(fd, iov, iov_cnt, true);
}

static _UNUSED ssize_t _jove_robust_readv_trash(int fd, struct iovec *iov,
                                                unsigned iov_cnt) {
  return _jove_robust_writev_readv_trash(fd, iov, iov_cnt, false);
}

//
// utilities
//

static _UNUSED unsigned _jove_read_pseudo_file(const char *path,
                                               char *out,
                                               size_t len) {
  int fd = _jove_open(path, O_RDONLY, S_IRWXU);
  if (fd < 0)
    _UNREACHABLE("could not open file from procfs. is it mounted?");

  unsigned n = 0;

  do {
    ssize_t ret = _jove_sys_read(fd, &out[n], len - n);

    if (ret == 0)
      break;

    if (ret < 0) {
      if (ret == -EINTR)
        continue;

      _UNREACHABLE();
    }

    n += ret;
  } while (len > n);

  if (_jove_sys_close(fd) < 0)
    _UNREACHABLE();

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

//
// for_each macros
//
#define array_for_each_p(elemp, arr)                                           \
  for ((elemp) = &arr[0]; ((elemp) - &arr[0]) < ARRAY_SIZE(arr); ++(elemp))

#define for_each_str_delim_know_end(s, delim, str, n)                          \
  for ((s) = &str[0]; (s) != &str[n];                                          \
       (s) = (char *)must_nonnull(_memchr((s), delim, (n) - ((s) - &str[0]))) + 1)

#define for_each_str_eos_delim_know_end(s, eos, delim, str, n)                 \
  for ((s) = &str[0], (eos) = (char *)must_nonnull(_memchr((s), delim, (n) - ((s) - &str[0]))); \
       (s) != &str[n];                                                                          \
       (s) = (eos)+1, (eos) = (char *)/*maybenull*/_memchr((s), delim, (n) - ((s) - &str[0])))

#define for_each_binary_paths(idx, pathp)                                      \
  for ((pathp) = _jove_binary_paths(idx); *(pathp); ++(pathp))

//
// /proc/<pid>/maps
//
#define for_each_in_proc_maps(map, maps, n)                                    \
  for_each_str_delim_know_end(map, '\n', maps, n)

#define for_each_line_eol_in_proc_maps(line, eol, maps, n)                     \
  for_each_str_eos_delim_know_end(line, eol, '\n', maps, n)

static _UNUSED uintptr_t _parse_stack_end_of_maps(char *maps, unsigned n) {
  char *line;
  char *eol;
  for_each_line_eol_in_proc_maps(line, eol, maps, n) {
    if (eol[-1] == ']' &&
        eol[-2] == 'k' &&
        eol[-3] == 'c' &&
        eol[-4] == 'a' &&
        eol[-5] == 't' &&
        eol[-6] == 's' &&
        eol[-7] == '[') {
      unsigned left = eol - line;

      char *dash = _memchr(line, '-', left);
      char *space = _memchr(line, ' ', left);

      _ASSERT(dash);
      _ASSERT(space);

      uint64_t max = _u64ofhexstr(dash + 1, space);
      return max;
    }
  }

  _UNREACHABLE();
}

static _UNUSED uintptr_t _end_of_normal_readable_map_beginning_at(
    uintptr_t Addr, char *maps, unsigned n) {
  char *line;
  char *eol;
  for_each_line_eol_in_proc_maps(line, eol, maps, n) {
    if (eol[-1] == ']')
      continue; /* special mapping */

    struct {
      uintptr_t min, max;
    } vm;

    bool r = ({
      unsigned left = eol - line;

      char *dash = _memchr(line, '-', left);
      char *space = _memchr(line, ' ', left);

      _ASSERT(dash);
      _ASSERT(space);

      vm.min = _u64ofhexstr(line, dash);
      vm.max = _u64ofhexstr(dash + 1, space);

      char *rp = space + 1;
      *rp == 'r';
    });

    if (vm.min == Addr && r)
      return vm.max; /* yes */
  }

  return 0;
}

static _UNUSED uintptr_t _end_of_mapping_at_address(uintptr_t Addr, char *maps,
                                                    unsigned n) {
  char *line;
  char *eol;
  for_each_line_eol_in_proc_maps(line, eol, maps, n) {
    unsigned left = eol - line;

    struct {
      uint64_t min, max;
    } vm;

    {
      char *dash = _memchr(line, '-', left);
      char *space = _memchr(line, ' ', left);

      _ASSERT(dash);
      _ASSERT(space);

      vm.min = _u64ofhexstr(line, dash);
      vm.max = _u64ofhexstr(dash + 1, space);
    }

    if (Addr >= vm.min && Addr < vm.max)
      return vm.max;
  }

  return 0;
}

static _UNUSED size_t _sum_iovec_lengths(const struct iovec *iov, unsigned n) {
  size_t expected = 0;
  for (unsigned i = 0; i < n; ++i)
    expected += iov[i].iov_len;
  return expected;
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

static uintptr_t _jove_alloc_stack(void) {
  uintptr_t ret = _mmap_rw_anonymous_private_memory(JOVE_STACK_SIZE);
  if (IS_ERR_VALUE(ret))
    _UNREACHABLE("failed to allocate stack");

  //
  // create guard pages on both sides
  //
  uintptr_t beg = ret;
  uintptr_t end = beg + JOVE_STACK_SIZE;

  if (_jove_sys_mprotect(beg, JOVE_PAGE_SIZE, PROT_NONE) < 0)
    _UNREACHABLE("failed to create guard page #1");

  if (_jove_sys_mprotect(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, PROT_NONE) < 0)
    _UNREACHABLE("failed to create guard page #2");

  JOVE_TRACK_ALLOCATION(beg, JOVE_PAGE_SIZE, "beg-emustack");
  JOVE_TRACK_ALLOCATION(end - JOVE_PAGE_SIZE, JOVE_PAGE_SIZE, "end-emustack");
  JOVE_TRACK_ALLOCATION(beg + JOVE_PAGE_SIZE, JOVE_STACK_SIZE - 2 * JOVE_PAGE_SIZE, "emustack");

  return beg;
}

static void _jove_free_stack(uintptr_t beg) {
  if (_jove_sys_munmap(beg, JOVE_STACK_SIZE) < 0)
    _UNREACHABLE("failed to deallocate stack");

  JOVE_UNTRACK_ALLOCATION(beg, JOVE_STACK_SIZE);
}

//
// buffer management
//

typedef struct jove_buffer_t {
  void *ptr;
  unsigned len;
} jove_buffer_t;

static jove_buffer_t _jove_alloc_buffer(size_t len) {
  len = QEMU_ALIGN_UP(len, JOVE_PAGE_SIZE);

  uintptr_t ret = _mmap_rw_anonymous_private_memory(len);
  if (IS_ERR_VALUE(ret))
    _UNREACHABLE("failed to allocate buffer");

  return (jove_buffer_t){.ptr = (void *)ret, .len = len};
}

static void _jove_free_buffer(const jove_buffer_t *buff) {
  if (_jove_sys_munmap((uintptr_t)buff->ptr, buff->len) < 0)
    _UNREACHABLE("failed to deallocate buffer");
}

#define JOVE_SCOPED_BUFF(var, len)                                             \
  const jove_buffer_t __##var##_buff _CLEANUP(_jove_free_buffer) =             \
      _jove_alloc_buffer(len);                                                 \
  var = (char *)__##var##_buff.ptr

//
// string management
//

typedef struct jove_saved_char_t {
  char *p;
  char ch;
} jove_saved_char_t;

static jove_saved_char_t _jove_save_and_set_char(char *const p, const char ch) {
  jove_saved_char_t sav;

  _ASSERT(p);

  /* save */
  sav.ch = *p;

  /* set */
  *p = ch;

  sav.p = p;
  return sav;
}

static void _jove_restore_char(const jove_saved_char_t *sav) {
  *sav->p = sav->ch;
}

#define set_restore_char(p, ch)                                                \
  const jove_saved_char_t UNIQUE_VAR_NAME(__set_restore)                       \
      _CLEANUP(_jove_restore_char) = _jove_save_and_set_char(p, ch)

#define set_restore_char_safe(p, ch, expected)                                 \
  _ASSERT(*((const char *)(p)) == expected);                                   \
  set_restore_char(p, ch)

//
// /proc/self/maps
//
#define LOAD_PROC_SELF_MAPS(var, len)                                          \
  JOVE_SCOPED_BUFF(var, JOVE_MAX_PROC_MAPS);                                   \
  len = _jove_read_pseudo_file("/proc/self/maps", var, JOVE_MAX_PROC_MAPS)

static _UNUSED bool _description_of_address_for_maps(char *out,
                                                     uintptr_t Addr,
                                                     char *maps,
                                                     const unsigned n) {
  char *line;
  char *eol;
  for_each_line_eol_in_proc_maps(line, eol, maps, n) {
    unsigned left = eol - line;

    struct {
      uintptr_t min, max;
    } vm;

    char *const dash = _memchr(line, '-', left);
    char *const space = _memchr(line, ' ', left);

    _ASSERT(dash);
    _ASSERT(space);

    vm.min = _u64ofhexstr(line, dash);
    vm.max = _u64ofhexstr(dash + 1, space);

    //
    // does the given address exist within this mapping?
    //
    if (!(Addr >= vm.min && Addr < vm.max))
      continue;

    char *const pp = space + 4;
    char *const off = pp + 2;
    char *const eooff = _memchr(off, ' ', eol - off);
    _ASSERT(eooff);

    uint64_t offset = _u64ofhexstr(off, eooff);

    //
    // description is base+offset
    //
    char *const fwdslash = _memchr(line, '/', left);
    char *const leftsqbr = _memchr(line, '[', left);

    *out = '\0';

    if (fwdslash) { /* e.g. /usr/bin/cat */
      set_restore_char_safe(eol, '\0', '\n');
      _strcat(out, fwdslash);
    } else if (leftsqbr) { /* e.g. [vdso] */
      set_restore_char_safe(eol, '\0', '\n');
      _strcat(out, leftsqbr);
    } else { /* anonymous mapping */
      set_restore_char_safe(dash, '\0', '-');
      _strcat(out, line);

#ifdef JOVE_TRACK_ALLOCATIONS
      {
        const char *desc = _jove_rt_description_for_alloc(vm.min);
        if (desc) {
          _strcat(out, __ANSI_BOLD_GREEN " <");
          _strcat(out, desc);
          _strcat(out, ">" __ANSI_NORMAL_COLOR);
        }
      }
#endif
    }

    _strcat(out, "+0x");

    uint64_t Offset = (Addr - vm.min) + offset;

    {
      char buff[65];

      _uint_to_string(Offset, buff, 0x10);
      _strcat(out, buff);
    }

    return true;
  }

  return false;
}

//
// /proc/self/environ
//
#define for_each_in_environ(env, environ, n)                                   \
  for_each_str_delim_know_end(env, '\0', environ, n)

/* caches /proc/self/environ */
static _UNUSED char *_get_environ(unsigned *np) {
  static jove_buffer_t envs = {0};
  static unsigned n = 0;
  static mutex_t _mtx = JOVE_MUTEX_INIT;

  if (!envs.ptr) {
    _mutex_lock(&_mtx);

    if (!envs.ptr) {
      envs = _jove_alloc_buffer(JOVE_MAX_ENVIRON);
      n = _jove_read_pseudo_file("/proc/self/environ", envs.ptr, envs.len);
    }

    _mutex_unlock(&_mtx);
  }

  *np = n;
  return envs.ptr;
}

static _UNUSED char *_getenv(const char *name) {
  const unsigned name_len = _strlen(name);

  unsigned n;
  char *const envs = _get_environ(&n);

  char *env;
  for_each_in_environ(env, envs, n) {
    const char *s1 = name;
    char *s2 = env;
    for (;;) {
      char ch1 = *s1++;
      char ch2 = *s2++;

      if (ch1 != ch2)
        break;

      if ((s1 - name) == name_len) {
        if (*s2 == '=')
          return s2 + 1;

        break;
      }
    }
  }

  return NULL;
}
