  if (exception != 17 /* EXCP_SYSCALL */) {
    __builtin_trap();
    __builtin_unreachable();
  }

void do_syscall(CPUMIPSState *);

  do_syscall(env);
} /* see qemu/target/mips/tcg/exception.c */

#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>

static const char *syscall_names[] = {
#define ___SYSCALL(nr, nm) [nr] = #nm,
#include "syscalls.inc.h"
};

#define JOVE_CRASH_MODE 'a'

#include "jove.macros.h"
#include "jove.constants.h"

#define JOVE_SYS_ATTR _INL _UNUSED

#include "jove.util.c"

void do_syscall(CPUMIPSState *env) {
  unsigned long sysnum = env->active_tc.gpr[2];

#define env_a1 env->active_tc.gpr[4]
#define env_a2 env->active_tc.gpr[5]
#define env_a3 env->active_tc.gpr[6]
#define env_a4 env->active_tc.gpr[7]
#define env_a5 env->active_tc.gpr[8]
#define env_a6 env->active_tc.gpr[9]

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

  //
  // perform the call
  //

  /* For historic reasons the pipe(2) syscall on MIPS returns results in
   * registers $v0 and $v1 */
  if (sysnum == 5021 /* sysm_pipe */) {
    __builtin_trap(); /* TODO */
    __builtin_unreachable();
  }

  switch (sysnum) {
#define ___SYSCALL0(nr, nm)                                                    \
  case nr: {                                                                   \
    register long r7 asm("$7");                                                \
    register long r2 asm("$2");                                                \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(r2), "=r"(r7)                                          \
                 : "IK"(nr)                                                    \
                 : __SYSCALL_CLOBBERS);                                        \
    env->active_tc.gpr[7] = r7;                                                \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  case nr: {                                                                   \
    register long __a0 asm("$4") = (long)_a1;                                  \
    register long r7 asm("$7");                                                \
    register long r2 asm("$2");                                                \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(r2), "=r"(r7)                                          \
                 : "IK"(nr), "r"(__a0)                                         \
                 : __SYSCALL_CLOBBERS);                                        \
    env->active_tc.gpr[7] = r7;                                                \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  case nr: {                                                                   \
    register long __a0 asm("$4") = (long)_a1;                                  \
    register long __a1 asm("$5") = (long)_a2;                                  \
    register long r7 asm("$7");                                                \
    register long r2 asm("$2");                                                \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(r2), "=r"(r7)                                          \
                 : "IK"(nr), "r"(__a0), "r"(__a1)                              \
                 : __SYSCALL_CLOBBERS);                                        \
    env->active_tc.gpr[7] = r7;                                                \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  case nr: {                                                                   \
    register long __a0 asm("$4") = (long)_a1;                                  \
    register long __a1 asm("$5") = (long)_a2;                                  \
    register long __a2 asm("$6") = (long)_a3;                                  \
    register long r7 asm("$7");                                                \
    register long r2 asm("$2");                                                \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(r2), "=r"(r7)                                          \
                 : "IK"(nr), "r"(__a0), "r"(__a1), "r"(__a2)                   \
                 : __SYSCALL_CLOBBERS);                                        \
    env->active_tc.gpr[7] = r7;                                                \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  case nr: {                                                                   \
    register long __a0 asm("$4") = (long)_a1;                                  \
    register long __a1 asm("$5") = (long)_a2;                                  \
    register long __a2 asm("$6") = (long)_a3;                                  \
    register long __a3 asm("$7") = (long)_a4;                                  \
    register long r2 asm("$2");                                                \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(r2), "+r"(__a3)                                        \
                 : "IK"(nr), "r"(__a0), "r"(__a1), "r"(__a2)                   \
                 : __SYSCALL_CLOBBERS);                                        \
    env->active_tc.gpr[7] = __a3;                                              \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  case nr: {                                                                   \
    register long __a0 asm("$4") = (long)_a1;                                  \
    register long __a1 asm("$5") = (long)_a2;                                  \
    register long __a2 asm("$6") = (long)_a3;                                  \
    register long __a3 asm("$7") = (long)_a4;                                  \
    register long __a4 asm("$8") = (long)_a5;                                  \
    register long r2 asm("$2");                                                \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(r2), "+r"(__a3)                                        \
                 : "IK"(nr), "r"(__a0), "r"(__a1), "r"(__a2), "r"(__a4)        \
                 : __SYSCALL_CLOBBERS);                                        \
    env->active_tc.gpr[7] = __a3;                                              \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  case nr: {                                                                   \
    register long __a0 asm("$4") = (long)_a1;                                  \
    register long __a1 asm("$5") = (long)_a2;                                  \
    register long __a2 asm("$6") = (long)_a3;                                  \
    register long __a3 asm("$7") = (long)_a4;                                  \
    register long __a4 asm("$8") = (long)_a5;                                  \
    register long __a5 asm("$9") = (long)_a6;                                  \
    register long r2 asm("$2");                                                \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(r2), "+r"(__a3)                                        \
                 : "IK"(nr), "r"(__a0), "r"(__a1), "r"(__a2), "r"(__a4),       \
                   "r"(__a5)                                                   \
                 : __SYSCALL_CLOBBERS);                                        \
    env->active_tc.gpr[7] = __a3;                                              \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#include "syscalls.inc.h"

  default:
    __builtin_trap();
    __builtin_unreachable();
  }
}

static void ____(void) { /* see qemu/target/mips/tcg/exception.c */
