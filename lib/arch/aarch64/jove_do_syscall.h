  if (excp != EXCP_SWI) {
    __builtin_trap();
    __builtin_unreachable();
  }

void do_syscall(CPUARMState *);

  do_syscall(env);
} /* see qemu/target/arm/tcg/op_helper.c */

#define JOVE_SYS_ATTR __attribute__((noinline))

#include "jove_sys.h"

void do_syscall(CPUARMState *env) {
  unsigned long sysnum = env->xregs[8];

#define env_a1 env->xregs[0]
#define env_a2 env->xregs[1]
#define env_a3 env->xregs[2]
#define env_a4 env->xregs[3]
#define env_a5 env->xregs[4]
#define env_a6 env->xregs[5]

  long _a1 = env_a1;
  long _a2 = env_a2;
  long _a3 = env_a3;
  long _a4 = env_a4;
  long _a5 = env_a5;
  long _a6 = env_a6;

#undef env_a1
#undef env_a2
#undef env_a3
#undef env_a4
#undef env_a5
#undef env_a6

  unsigned long sysret;
  switch (sysnum) {
#define ___SYSCALL0(nr, nm)                                                    \
  case nr:                                                                     \
    sysret = _jove_sys_##nm();                                                 \
    break;

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  case nr:                                                                     \
    sysret = _jove_sys_##nm(_a1);                                              \
    break;

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  case nr:                                                                     \
    sysret = _jove_sys_##nm(_a1, _a2);                                         \
    break;

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  case nr:                                                                     \
    sysret = _jove_sys_##nm(_a1, _a2, _a3);                                    \
    break;

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  case nr:                                                                     \
    sysret = _jove_sys_##nm(_a1, _a2, _a3, _a4);                               \
    break;

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  case nr:                                                                     \
    sysret = _jove_sys_##nm(_a1, _a2, _a3, _a4, _a5);                          \
    break;

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  case nr:                                                                     \
    sysret = _jove_sys_##nm(_a1, _a2, _a3, _a4, _a5, _a6);                     \
    break;

#include "syscalls.inc.h"

  default:
    __builtin_trap();
    __builtin_unreachable();
  }

  env->xregs[0] = sysret;
}

static void ____(void) { /* see qemu/target/arm/tcg/op_helper.c */
