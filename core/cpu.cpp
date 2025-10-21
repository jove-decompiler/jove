#include "cpu.h"
#include "assert.h"

#include <sched.h>
#include <errno.h>

namespace jove {

unsigned cpu_count(void) {
  cpu_set_t cpu_mask;
  aassert(sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask) == 0);

  return CPU_COUNT(&cpu_mask);
}

}
