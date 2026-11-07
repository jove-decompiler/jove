#include "kernel.h"
#include "sys.h"

#include <linux/fs.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

namespace jove {
namespace kernel {

namespace NR {
#define ___SYSCALL(nr, nm) static constexpr unsigned nm = nr;
#include "syscalls.inc.h"
}

bool has_ProcMapQuery(void) {
  int fd;
  do {} while ((fd = _jove_sys_openat(-1, "/proc/self/maps", O_RDONLY, 0)) == -EINTR);
  const bool Succ = _jove_sys_ioctl(fd, PROCMAP_QUERY, NULL) == -EFAULT;
  ::close(fd);
  return Succ;
}

bool has_io_uring(void) {
  return _jove_sys_io_uring_setup(0, NULL) == EFAULT;
}

}
}
