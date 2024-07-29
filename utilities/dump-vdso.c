#include "jove.macros.h"

#define JOVE_SYS_ATTR _NOINL _UNUSED
#define JOVE_CRASH_MODE 'a'

#include "jove.util.c"
#include "jove.start.c"

struct vdso_t {
  void *ptr;
  unsigned len;
};

/* TODO refactor */
static _INL struct vdso_t _get_vdso(char *maps, const unsigned n) {
  char *const beg = &maps[0];
  char *const end = &maps[n];

  char *eol;
  for (char *line = beg; line != end; line = eol + 1) {
    unsigned left = n - (line - beg);

    //
    // find the end of the current line
    //
    eol = _memchr(line, '\n', left);
    _ASSERT(eol);

    //
    // second hex address
    //
    if (eol[-1] == ']' &&
        eol[-2] == 'o' &&
        eol[-3] == 's' &&
        eol[-4] == 'd' &&
        eol[-5] == 'v' &&
        eol[-6] == '[') {
      char *space = _memchr(line, ' ', left);
      _ASSERT(space);

      char *rp = space + 1;
      char *xp = space + 3;

      if (*rp != 'r') _UNREACHABLE("[vdso] appears to not be readable...");
      if (*xp != 'x') _UNREACHABLE("[vdso] appears to not be executable...");

      char *dash = _memchr(line, '-', left);
      _ASSERT(dash);

      uint64_t min = _u64ofhexstr(line, dash);
      uint64_t max = _u64ofhexstr(dash + 1, space);

      return (struct vdso_t){.ptr = (void *)min, .len = max - min};
    }
  }

  //_DUMP_WITH_LEN(maps, n);
  _UNREACHABLE("failed to find [vdso]");
}

_NORET
_HIDDEN
void _jove_begin(void) {
  JOVE_BUFF(maps, JOVE_MAX_PROC_MAPS);
  unsigned maps_n = _jove_read_pseudo_file("/proc/self/maps", _maps.ptr, _maps.len);

  struct vdso_t vdso = _get_vdso(maps, maps_n);

  _RELEASE_ASSERT(_jove_robust_write(1, vdso.ptr, vdso.len) == vdso.len);

  _jove_sys_exit_group(0);
  __UNREACHABLE();
}
