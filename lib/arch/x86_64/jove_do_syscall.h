void do_syscall(CPUX86State *);

  do_syscall(env);
} /* see qemu/target/i386/tcg/user/seg_helper.c */

#define _HIDDEN __attribute__((visibility("hidden")))
#define _INL    __attribute__((always_inline))

//
// Some syscalls like clone do not tolerate a return instruction after
// the syscall instruction. Marking the syscall functions with the
// `always_inline` attribute accommodates such syscalls as inlining
// eliminates the return instruction.
//
#define JOVE_SYS_ATTR _INL
#include "jove_sys.h"

#ifdef JOVE_DFSAN

#define SYSEXIT(nm) __dfs_sys_exit_##nm
#define SYSENTR(nm) __dfs_sys_entr_##nm

//
// declare dfsan syscall hooks
//
#define ___SYSCALL0(nr, nm)                                                    \
  void SYSEXIT(nm)(long sysret);
#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  void SYSEXIT(nm)(long sysret, t1 a1);
#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  void SYSEXIT(nm)(long sysret, t1 a1, t2 a2);
#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  void SYSEXIT(nm)(long sysret, t1 a1, t2 a2, t3 a3);
#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  void SYSEXIT(nm)(long sysret, t1 a1, t2 a2, t3 a3, t4 a4);
#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  void SYSEXIT(nm)(long sysret, t1 a1, t2 a2, t3 a3, t4 a4, t5 a5);
#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  void SYSEXIT(nm)(long sysret, t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6);

#define ___DFSAN_SYSEXITS
#include "syscalls.inc.h"
#undef ___DFSAN_SYSEXITS

#define ___SYSCALL0(nr, nm)                                                    \
  void SYSENTR(nm)();
#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  void SYSENTR(nm)(t1 a1);
#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  void SYSENTR(nm)(t1 a1, t2 a2);
#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  void SYSENTR(nm)(t1 a1, t2 a2, t3 a3);
#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  void SYSENTR(nm)(t1 a1, t2 a2, t3 a3, t4 a4);
#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  void SYSENTR(nm)(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5);
#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  void SYSENTR(nm)(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6);

#define ___DFSAN_SYSENTRS
#include "syscalls.inc.h"
#undef ___DFSAN_SYSENTRS

#endif /* JOVE_DFSAN */

__attribute__((naked)) static void _jove_restore_rt(void) {
  asm volatile("mov $0xf, %rax\n"
               "syscall\n"
               "hlt");
}

void do_syscall(CPUX86State *env) {
  unsigned long sysnum = env->regs[R_EAX];

#define env_a1 env->regs[R_EDI]
#define env_a2 env->regs[R_ESI]
#define env_a3 env->regs[R_EDX]
#define env_a4 env->regs[R_R10]
#define env_a5 env->regs[R_R8]
#define env_a6 env->regs[R_R9]

#ifdef JOVE_DFSAN

  //
  // call pre hooks
  //
  switch (sysnum) {
#define ___SYSCALL0(nr, nm)                                                    \
  case nr:                                                                     \
    SYSENTR(nm)();                                                             \
    break;
#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  case nr:                                                                     \
    SYSENTR(nm)((t1)env_a1);                                                   \
    break;
#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  case nr:                                                                     \
    SYSENTR(nm)((t1)env_a1,                                                    \
                (t2)env_a2);                                                   \
    break;
#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  case nr:                                                                     \
    SYSENTR(nm)((t1)env_a1,                                                    \
                (t2)env_a2,                                                    \
                (t3)env_a3);                                                   \
    break;
#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  case nr:                                                                     \
    SYSENTR(nm)((t1)env_a1,                                                    \
                (t2)env_a2,                                                    \
                (t3)env_a3,                                                    \
                (t4)env_a4);                                                   \
    break;
#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  case nr:                                                                     \
    SYSENTR(nm)((t1)env_a1,                                                    \
                (t2)env_a2,                                                    \
                (t3)env_a3,                                                    \
                (t4)env_a4,                                                    \
                (t5)env_a5);                                                   \
    break;
#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  case nr:                                                                     \
    SYSENTR(nm)((t1)env_a1,                                                    \
                (t2)env_a2,                                                    \
                (t3)env_a3,                                                    \
                (t4)env_a4,                                                    \
                (t5)env_a5,                                                    \
                (t6)env_a6);                                                   \
    break;

#define ___DFSAN
#define ___DFSAN_SYSENTRS
#include "syscalls.inc.h"
#undef ___DFSAN_SYSENTRS
#undef ___DFSAN

  default:
    break;
  }

#endif

  //
  // hacks
  //
  if (sysnum == 13 /* rt_sigaction */) {
    unsigned long *act = (unsigned long *)env_a2;
    act[2] = (unsigned long)_jove_restore_rt;
  }

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
    sysret = _jove_sys_##nm(env_a1);                                           \
    break;

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  case nr:                                                                     \
    sysret = _jove_sys_##nm(env_a1,                                            \
                            env_a2);                                           \
    break;

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  case nr:                                                                     \
    sysret = _jove_sys_##nm(env_a1,                                            \
                            env_a2,                                            \
                            env_a3);                                           \
    break;

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  case nr:                                                                     \
    sysret = _jove_sys_##nm(env_a1,                                            \
                            env_a2,                                            \
                            env_a3,                                            \
                            env_a4);                                           \
    break;

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  case nr:                                                                     \
    sysret = _jove_sys_##nm(env_a1,                                            \
                            env_a2,                                            \
                            env_a3,                                            \
                            env_a4,                                            \
                            env_a5);                                           \
    break;

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  case nr:                                                                     \
    sysret = _jove_sys_##nm(env_a1,                                           \
                            env_a2,                                           \
                            env_a3,                                           \
                            env_a4,                                           \
                            env_a5,                                           \
                            env_a6);                                          \
    break;

#include "syscalls.inc.h"

  default:
    __builtin_trap();
    __builtin_unreachable();
  }

#ifdef JOVE_DFSAN

  //
  // call post hooks
  //
  switch (sysnum) {
#define ___SYSCALL0(nr, nm)                                                    \
  case nr:                                                                     \
    SYSEXIT(nm)(sysret);                                                       \
    break;
#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  case nr:                                                                     \
    SYSEXIT(nm)(sysret, (t1)env_a1);                                           \
    break;
#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  case nr:                                                                     \
    SYSEXIT(nm)(sysret, (t1)env_a1,                                            \
                        (t2)env_a2);                                           \
    break;
#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  case nr:                                                                     \
    SYSEXIT(nm)(sysret, (t1)env_a1,                                            \
                        (t2)env_a2,                                            \
                        (t3)env_a3);                                           \
    break;
#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  case nr:                                                                     \
    SYSEXIT(nm)(sysret, (t1)env_a1,                                            \
                        (t2)env_a2,                                            \
                        (t3)env_a3,                                            \
                        (t4)env_a4);                                           \
    break;
#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  case nr:                                                                     \
    SYSEXIT(nm)(sysret, (t1)env_a1,                                            \
                        (t2)env_a2,                                            \
                        (t3)env_a3,                                            \
                        (t4)env_a4,                                            \
                        (t5)env_a5);                                           \
    break;
#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  case nr:                                                                     \
    SYSEXIT(nm)(sysret, (t1)env_a1,                                            \
                        (t2)env_a2,                                            \
                        (t3)env_a3,                                            \
                        (t4)env_a4,                                            \
                        (t5)env_a5,                                            \
                        (t6)env_a6);                                           \
    break;

#define ___DFSAN
#define ___DFSAN_SYSEXITS
#include "syscalls.inc.h"
#undef ___DFSAN_SYSEXITS
#undef ___DFSAN

  default:
    break;
  }

#endif

  env->regs[R_EAX] = sysret;
}

#undef SYSENTR
#undef SYSEXIT

static void ____(void) { /* see qemu/target/i386/tcg/user/seg_helper.c */
