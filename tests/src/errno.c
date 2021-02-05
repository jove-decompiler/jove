#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>

int main(int argc, char **argv) {
  int ret = mkdir("/foo", 0777);
  if (ret < 0) {
    int err = errno;

    printf("mkdir failed with errno %d (%s)\n", err, strerror(err));
    return 1;
  }

  return 0;
}
