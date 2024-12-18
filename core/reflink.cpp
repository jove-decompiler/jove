#include "reflink.h"
#include "fd.h"

#include <linux/fs.h> /* For FICLONE and FICLONERANGE */
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

namespace jove {

int cp_reflink_to(int src_fd, const char *dst_filename, uint64_t len) {
  scoped_fd dst_fd(::open(dst_filename, O_CREAT | O_TRUNC | O_WRONLY, 0644));
  if (!dst_fd)
    return -1;

  return cp_reflink(src_fd, dst_fd.get(), len);
}

int cp_reflink(int src_fd, int dst_fd, uint64_t len) {
  int ret = ioctl(dst_fd, FICLONE, src_fd);
  if (ret < 0) {
    // try FICLONERANGE
    struct file_clone_range clone_range;
    clone_range.src_fd = src_fd;
    clone_range.src_offset = 0;
    clone_range.src_length = len;
    clone_range.dest_offset = 0;

    return ioctl(dst_fd, FICLONERANGE, &clone_range);
  }
  return ret;
}

}
