#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static __attribute__((noinline)) int vulnerable_function(const char *str);

int main(int argc, char **argv) {
  if (argc != 2) {
    puts("usage: stack_buffer_overrun string");
    return 0;
  }

  int n = vulnerable_function(argv[1]);
  printf("n is %d\n", n);

  return 0;
}

#define __COLOR_PREFIX "\033["
#define __COLOR_SUFFIX "m"

#define __CLR_BOLD_RED __COLOR_PREFIX "1;31" __COLOR_SUFFIX
#define __CLR_RED      __COLOR_PREFIX "31"   __COLOR_SUFFIX
#define __CLR_NORMAL   __COLOR_PREFIX "0"    __COLOR_SUFFIX

#define BUFSIZE 16

int vulnerable_function(const char *str) {
  char buf[BUFSIZE];
  strcpy(buf, str);

#if 0
  printf("buf: ");
#endif

  printf("buf: %s\n", buf);

  int res = 0;
  int n = strlen(str);
  for (unsigned i = 0; i < n; ++i) {
    char ch = str[i];
    res += ch;

#if 0
    char *fp = __builtin_frame_address(0);

    const char *Prefix;
    if (i < sizeof(buf))
      Prefix = "";
    else if (&buf[i] >= fp)
      Prefix = __CLR_BOLD_RED;
    else
      Prefix = __CLR_RED;

    printf("%s%02X%s",
           Prefix,
           (unsigned char)ch,
           __CLR_NORMAL);
#endif
  }

#if 0
  printf("\n");
#endif

  return res;
}
