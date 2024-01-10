  if (intno != 0x80) {
    __builtin_trap();
    __builtin_unreachable();
  }

void do_syscall(CPUX86State *);

  do_syscall(env);
} /* see qemu/target/i386/tcg/excp_helper.c */

#define _NOINL  __attribute__((noinline))
#define _HIDDEN __attribute__((visibility("hidden")))

//
// Some syscalls like clone do not tolerate a return instruction after
// the syscall instruction. Marking the syscall functions with the
// `always_inline` attribute accommodates such syscalls as inlining
// eliminates the return instruction.
//
#define JOVE_SYS_ATTR _NOINL _HIDDEN
#include "jove_sys.h"

void do_syscall(CPUX86State *env) {
  //
  // this is a system call
  //
  unsigned long sysnum = env->regs[R_EAX];

#define env_a1 env->regs[R_EBX]
#define env_a2 env->regs[R_ECX]
#define env_a3 env->regs[R_EDX]
#define env_a4 env->regs[R_ESI]
#define env_a5 env->regs[R_EDI]
#define env_a6 env->regs[R_EBP]

  const unsigned long _a1 = env_a1;
  const unsigned long _a2 = env_a2;
  const unsigned long _a3 = env_a3;
  const unsigned long _a4 = env_a4;
  const unsigned long _a5 = env_a5;
  const unsigned long _a6 = env_a6;

  //
  // perform the call
  //
  long sysret;
  switch (sysnum) {
#define ___SYSCALL0(nr, nm)                                                    \
  case nr:                                                                     \
    sysret = _jove_sys_##nm();                                                 \
    break;

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  case nr:                                                                     \
    sysret = _jove_sys_##nm((t1)_a1);                                          \
    break;

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  case nr:                                                                     \
    sysret = _jove_sys_##nm((t1)_a1, (t2)_a2);                                 \
    break;

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  case nr:                                                                     \
    sysret = _jove_sys_##nm((t1)_a1, (t2)_a2, (t3)_a3);                        \
    break;

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  case nr:                                                                     \
    sysret = _jove_sys_##nm((t1)_a1, (t2)_a2, (t3)_a3, (t4)_a4);               \
    break;

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  case nr:                                                                     \
    sysret = _jove_sys_##nm((t1)_a1, (t2)_a2, (t3)_a3, (t4)_a4, (t5)_a5);      \
    break;

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  case nr:                                                                     \
    sysret =                                                                   \
        _jove_sys_##nm((t1)_a1, (t2)_a2, (t3)_a3, (t4)_a4, (t5)_a5, (t6)_a6);  \
    break;

#include "syscalls.inc.h"

  default:
    __builtin_trap();
    __builtin_unreachable();
  }

  env->regs[R_EAX] = sysret;
}

static void ____(void) { /* see qemu/target/i386/tcg/excp_helper.c */
