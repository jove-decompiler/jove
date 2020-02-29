#ifndef JOVE_SYS_ATTR
#error
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/capability.h>
#include <sys/quota.h>
#include <sys/epoll.h>
#include <sched.h>
#include <linux/aio_abi.h>
#include <mqueue.h>
#include <keyutils.h>
#include <linux/bpf.h>

#ifndef __user
#define __user
#endif

#define __SYSCALL_CLOBBERS "$1", "$3", "$10", "$11", "$12", "$13", \
          "$14", "$15", "$24", "$25", "hi", "lo", "memory"

#define __SYSCALL_ASM ".set\tnoreorder\n\t" \
                      "li\t%0, %2\n\t" \
                      "syscall\n\t" \
                      ".set\treorder"

#define ___SYSCALL0(nr, nm)                                                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(void) {                             \
    register long __s0 asm("$16") __attribute__((unused)) = (0);               \
                                                                               \
    register long __v0 asm("$2");                                              \
    register long __a3 asm("$7");                                              \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "=r"(__a3)                                      \
                 : "IK"(nr)                                                    \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    long res = __v0;                                                           \
    {                                                                          \
      long _sc_err = __a3;                                                     \
      if (_sc_err)                                                             \
        res = -_sc_err;                                                        \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1) {                            \
    register long __s0 asm("$16") __attribute__((unused)) = (0);               \
                                                                               \
    register long __v0 asm("$2");                                              \
    register long __a0 asm("$4") = (long)a1;                                   \
    register long __a3 asm("$7");                                              \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "=r"(__a3)                                      \
                 : "IK"(nr), "r"(__a0)                                         \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    long res = __v0;                                                           \
    {                                                                          \
      long _sc_err = __a3;                                                     \
      if (_sc_err)                                                             \
        res = -_sc_err;                                                        \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2) {                     \
    register long __s0 asm("$16") __attribute__((unused)) = (0);               \
                                                                               \
    register long __v0 asm("$2");                                              \
    register long __a0 asm("$4") = (long)a1;                                   \
    register long __a1 asm("$5") = (long)a2;                                   \
    register long __a3 asm("$7");                                              \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "=r"(__a3)                                      \
                 : "IK"(nr), "r"(__a0), "r"(__a1)                              \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    long res = __v0;                                                           \
    {                                                                          \
      long _sc_err = __a3;                                                     \
      if (_sc_err)                                                             \
        res = -_sc_err;                                                        \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3) {              \
    register long __s0 asm("$16") __attribute__((unused)) = (0);               \
                                                                               \
    register long __v0 asm("$2");                                              \
    register long __a0 asm("$4") = (long)a1;                                   \
    register long __a1 asm("$5") = (long)a2;                                   \
    register long __a2 asm("$6") = (long)a3;                                   \
    register long __a3 asm("$7");                                              \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "=r"(__a3)                                      \
                 : "IK"(nr), "r"(__a0), "r"(__a1), "r"(__a2)                   \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    long res = __v0;                                                           \
    {                                                                          \
      long _sc_err = __a3;                                                     \
      if (_sc_err)                                                             \
        res = -_sc_err;                                                        \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4) {       \
    register long __s0 asm("$16") __attribute__((unused)) = (0);               \
                                                                               \
    register long __v0 asm("$2");                                              \
    register long __a0 asm("$4") = (long)a1;                                   \
    register long __a1 asm("$5") = (long)a2;                                   \
    register long __a2 asm("$6") = (long)a3;                                   \
    register long __a3 asm("$7") = (long)a4;                                   \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "+r"(__a3)                                      \
                 : "IK"(nr), "r"(__a0), "r"(__a1), "r"(__a2)                   \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    long res = __v0;                                                           \
    {                                                                          \
      long _sc_err = __a3;                                                     \
      if (_sc_err)                                                             \
        res = -_sc_err;                                                        \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4,         \
                                           t5 a5) {                            \
    register long __s0 asm("$16") __attribute__((unused)) = (0);               \
                                                                               \
    register long __v0 asm("$2");                                              \
    register long __a0 asm("$4") = (long)a1;                                   \
    register long __a1 asm("$5") = (long)a2;                                   \
    register long __a2 asm("$6") = (long)a3;                                   \
    register long __a3 asm("$7") = (long)a4;                                   \
    register long __a4 asm("$8") = (long)a5;                                   \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "+r"(__a3)                                      \
                 : "IK"(nr), "r"(__a0), "r"(__a1), "r"(__a2), "r"(__a4)        \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    long res = __v0;                                                           \
    {                                                                          \
      long _sc_err = __a3;                                                     \
      if (_sc_err)                                                             \
        res = -_sc_err;                                                        \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5,  \
                                           t6 a6) {                            \
    register long __s0 asm("$16") __attribute__((unused)) = (0);               \
                                                                               \
    register long __v0 asm("$2");                                              \
    register long __a0 asm("$4") = (long)a1;                                   \
    register long __a1 asm("$5") = (long)a2;                                   \
    register long __a2 asm("$6") = (long)a3;                                   \
    register long __a3 asm("$7") = (long)a4;                                   \
    register long __a4 asm("$8") = (long)a5;                                   \
    register long __a5 asm("$9") = (long)a6;                                   \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "+r"(__a3)                                      \
                 : "IK"(nr), "r"(__a0), "r"(__a1), "r"(__a2), "r"(__a4),       \
                   "r"(__a5)                                                   \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    long res = __v0;                                                           \
    {                                                                          \
      long _sc_err = __a3;                                                     \
      if (_sc_err)                                                             \
        res = -_sc_err;                                                        \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#include "syscalls.inc.h"

#undef JOVE_SYS_ATTR
