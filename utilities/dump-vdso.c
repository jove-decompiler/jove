#include "jove.macros.h"

#define JOVE_SYS_ATTR _UNUSED
#define JOVE_CRASH_MODE 'a'

#include "jove.util.c.inc"
#include "jove.start.c.inc"

struct vdso_t {
  void *ptr;
  unsigned len;
};

static struct vdso_t _get_vdso(char *maps, const unsigned n) {
  char *line;
  char *eol;
  for_each_line_eol_in_proc_maps(line, eol, maps, n) {
    if (eol[-1] == ']' &&
        eol[-2] == 'o' &&
        eol[-3] == 's' &&
        eol[-4] == 'd' &&
        eol[-5] == 'v' &&
        eol[-6] == '[') {
      unsigned left = eol - line;

      char *space = _memchr(line, ' ', left);
//    _ASSERT(space);

      char *rp = space + 1;
      char *xp = space + 3;

//    _ASSERT(*rp == 'r' && "[vdso] is readable");
//    _ASSERT(*xp == 'x' && "[vdso] is executable");

      char *dash = _memchr(line, '-', left);
//    _ASSERT(dash);

      uint64_t min = _u64ofhexstr(line, dash);
      uint64_t max = _u64ofhexstr(dash + 1, space);

      return (struct vdso_t){.ptr = (void *)min, .len = max - min};
    }
  }

  return (struct vdso_t){.ptr = NULL, .len = 0u};
}

_NORET
_HIDDEN
_FLATTEN
void _jove_begin(void) {
  char *maps;
  unsigned n;

  char buff[16];

  buff[0] = '/';
  buff[1] = 'p';
  buff[2] = 'r';
  buff[3] = 'o';
  buff[4] = 'c';
  buff[5] = '/';
  buff[6] = 's';
  buff[7] = 'e';
  buff[8] = 'l';
  buff[9] = 'f';
  buff[10] = '/';
  buff[11] = 'm';
  buff[12] = 'a';
  buff[13] = 'p';
  buff[14] = 's';
  buff[15] = '\0';

  ___guarded_buff___(maps, JOVE_MAX_PROC_MAPS);                                   \
  n = _jove_read_pseudo_file(buff, maps, JOVE_MAX_PROC_MAPS);

  struct vdso_t vdso = _get_vdso(maps, n);

  int rc = 1;

  if (vdso.ptr) {
    if (_jove_robust_write(1, vdso.ptr, vdso.len) == vdso.len)
      rc = 0;
  } else {
    rc = 0;
  }

  for (;;)
    _jove_sys_exit_group(rc);

  __UNREACHABLE();
}
