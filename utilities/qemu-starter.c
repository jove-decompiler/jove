#include "jove.macros.h"

#define JOVE_SYS_ATTR _INL _UNUSED
#include "jove_sys.h"

_NORET _HIDDEN void _jove_start(void) {
  _jove_sys_exit_group(22);

  __builtin_trap();
  __builtin_unreachable();
}
