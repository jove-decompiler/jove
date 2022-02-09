#include <setjmp.h>
#include <stdio.h>

static jmp_buf env;

int foo(int n) {
  if (n % 10 == 1) {
    longjmp(env, 1);
  }

  printf("did not longjump! n=%d\n", n);

  return 0;
}

int main(int argc, char **argv) {
  int n = argc;

  if (setjmp(env) == 1) {
    printf("longjumped! n=%d\n", n);
    return 1;
  }

  return foo(n);
}
