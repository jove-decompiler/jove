#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>

#define EXECUTABLE_REGION_SIZE (4096 * 16)

#define _CTOR __attribute__((constructor))

static void PrintMessageOrDie(const char *format, ...);

_CTOR static void preload_init(void) {
  const char *fifo_path = getenv("JOVE_DYN_FIFO_PATH");
  if (!fifo_path)
    return;

  void *addr =
      mmap(0x0, EXECUTABLE_REGION_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANONYMOUS, -1L, 0);

  if (addr == MAP_FAILED) {
    PrintMessageOrDie("%s: mmap failed (%s)\n", __func__, strerror(errno));
    return;
  }

  (void)unlink(fifo_path);

  int fd = mkfifo(fifo_path, 0666);
  if (fd < 0) {
    PrintMessageOrDie("%s: mkfifo failed (%s)\n", __func__, strerror(errno));
    goto failure;
  }

  /* fd and addr are valid */

  {
    ssize_t ret;
    do
      ret = write(fd, &addr, sizeof(addr));
    while (ret < 0 && errno == EINTR);

    if (ret == sizeof(addr))
      goto success;

    PrintMessageOrDie("%s: write failed (gave %zd)\n", __func__, ret);
    goto failure;
  }

success:
  if (close(fd) < 0)
    PrintMessageOrDie("%s: close failed (%s)\n", __func__, strerror(errno));

failure:
  //
  // if we failed, unmap the region
  //
  if (munmap(addr, EXECUTABLE_REGION_SIZE) < 0)
    PrintMessageOrDie("%s: munmap failed (%s)\n", __func__, strerror(errno));
}

void PrintMessageOrDie(const char *format, ...) {
  va_list ap;
  va_start(ap, format);

  char buff[0x100];
  int len = vsnprintf(buff, sizeof(buff), format, ap);
  if (len < 0) {
    __builtin_trap();
    __builtin_unreachable();
  }

  ssize_t ret;
  do
    ret = write(STDERR_FILENO, buff, len);
  while (ret < 0 && errno == EINTR);

  if (ret != len) {
    __builtin_trap();
    __builtin_unreachable();
  }
}
