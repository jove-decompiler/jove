#include "procmap_query.h"
#include "fd.h"
#include "eintr.h"
#include "sys.h"

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>

namespace jove {
namespace ProcMapQuery {

int get(int fd, struct procmap_query &query) {
  return _jove_sys_ioctl(fd, PROCMAP_QUERY, &query);
}

}
}
