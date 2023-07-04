#define _INL     __attribute__((always_inline))
#define _NORET   __attribute__((noreturn))
#define _UNUSED  __attribute__((unused))
#define _HIDDEN  __attribute__((visibility("hidden")))

#define JOVE_SYS_ATTR _INL _UNUSED
#include "jove_sys.h"

_NORET _HIDDEN void _start(void) {
  _jove_sys_exit_group(22);

  __builtin_trap();
  __builtin_unreachable();
}
