#ifndef JOVE_SYS_H
#define JOVE_SYS_H

#include "jove_sys.pre.h.inc"

#if 0
#include <sys/types.h>
//#include <sys/stat.h>
#include <sys/vfs.h>
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
//#include <sys/sysinfo.h>
//#include <sys/capability.h>
//#include <sys/quota.h>
#include <sys/epoll.h>
#include <sched.h>
//#include <linux/aio_abi.h>
//#include <mqueue.h>
//#include <keyutils.h>
//#include <linux/bpf.h>

typedef int32_t __s32;
typedef unsigned long aio_context_t;
typedef unsigned long mqd_t;             /* XXX */
typedef unsigned long key_serial_t;      /* XXX */
typedef unsigned long cap_user_data_t;   /* XXX */
typedef unsigned long cap_user_header_t; /* XXX */

#ifndef __user
#define __user
#endif
#endif

#define __SYSCALL_CLOBBERS "$1", "$3", "$10", "$11", "$12", "$13", \
          "$14", "$15", "$24", "$25", "hi", "lo", "memory"

#define __SYSCALL_ASM ".set\tnoreorder\n\t" \
                      "li\t%0, %2\n\t" \
                      "syscall\n\t" \
                      ".set\treorder"

#define ___SYSCALL0(nr, nm)                                                    \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(void) {                          \
    register uint64_t __s0 asm("$16") __attribute__((unused)) = (0);           \
                                                                               \
    register uint64_t __v0 asm("$2");                                          \
    register uint64_t __a3 asm("$7");                                          \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "=r"(__a3)                                      \
                 : "IK"(nr)                                                    \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    int64_t res = __v0;                                                        \
    {                                                                          \
      int64_t _sc_err = __a3;                                                  \
      if (_sc_err)                                                             \
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  __HEADER(1)                                                                  \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(__PARAM(1, t1) a1) {             \
    register uint64_t __s0 asm("$16") __attribute__((unused)) = (0);           \
                                                                               \
    register uint64_t __v0 asm("$2");                                          \
    register uint64_t __a0 asm("$4") = (uint64_t)a1;                           \
    register uint64_t __a3 asm("$7");                                          \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "=r"(__a3)                                      \
                 : "IK"(nr), "r"(__a0)                                         \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    int64_t res = __v0;                                                        \
    {                                                                          \
      int64_t _sc_err = __a3;                                                  \
      if (_sc_err)                                                             \
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  __HEADER(2)                                                                  \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(\
      __PARAM(1, t1) a1,                                                       \
      __PARAM(2, t2) a2) {                                                     \
    register uint64_t __s0 asm("$16") __attribute__((unused)) = (0);           \
                                                                               \
    register uint64_t __v0 asm("$2");                                          \
    register uint64_t __a0 asm("$4") = (uint64_t)a1;                           \
    register uint64_t __a1 asm("$5") = (uint64_t)a2;                           \
    register uint64_t __a3 asm("$7");                                          \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "=r"(__a3)                                      \
                 : "IK"(nr), "r"(__a0), "r"(__a1)                              \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    int64_t res = __v0;                                                        \
    {                                                                          \
      int64_t _sc_err = __a3;                                                  \
      if (_sc_err)                                                             \
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  __HEADER(3)                                                                  \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm( \
      __PARAM(1, t1) a1,                                                             \
      __PARAM(2, t2) a2,                                                             \
      __PARAM(3, t3) a3) {                                                           \
    register uint64_t __s0 asm("$16") __attribute__((unused)) = (0);           \
                                                                               \
    register uint64_t __v0 asm("$2");                                           \
    register uint64_t __a0 asm("$4") = (uint64_t)a1;                                \
    register uint64_t __a1 asm("$5") = (uint64_t)a2;                                \
    register uint64_t __a2 asm("$6") = (uint64_t)a3;                                \
    register uint64_t __a3 asm("$7");                                           \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "=r"(__a3)                                      \
                 : "IK"(nr), "r"(__a0), "r"(__a1), "r"(__a2)                   \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    int64_t res = __v0;                                                        \
    {                                                                          \
      int64_t _sc_err = __a3;                                                  \
      if (_sc_err)                                                             \
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  __HEADER(4)                                                                  \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(\
      __PARAM(1, t1) a1,                                                       \
      __PARAM(2, t2) a2,                                                       \
      __PARAM(3, t3) a3,                                                       \
      __PARAM(4, t4) a4) {                                                     \
    register uint64_t __s0 asm("$16") __attribute__((unused)) = (0);           \
                                                                               \
    register uint64_t __v0 asm("$2");                                          \
    register uint64_t __a0 asm("$4") = (uint64_t)a1;                           \
    register uint64_t __a1 asm("$5") = (uint64_t)a2;                           \
    register uint64_t __a2 asm("$6") = (uint64_t)a3;                           \
    register uint64_t __a3 asm("$7") = (uint64_t)a4;                           \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "+r"(__a3)                                      \
                 : "IK"(nr), "r"(__a0), "r"(__a1), "r"(__a2)                   \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    int64_t res = __v0;                                                        \
    {                                                                          \
      int64_t _sc_err = __a3;                                                  \
      if (_sc_err)                                                             \
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  __HEADER(5)                                                                  \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(\
      __PARAM(1, t1) a1,   \
      __PARAM(2, t2) a2,   \
      __PARAM(3, t3) a3,   \
      __PARAM(4, t4) a4,   \
      __PARAM(5, t5) a5) { \
    register uint64_t __s0 asm("$16") __attribute__((unused)) = (0);           \
                                                                               \
    register uint64_t __v0 asm("$2");                                          \
    register uint64_t __a0 asm("$4") = (uint64_t)a1;                           \
    register uint64_t __a1 asm("$5") = (uint64_t)a2;                           \
    register uint64_t __a2 asm("$6") = (uint64_t)a3;                           \
    register uint64_t __a3 asm("$7") = (uint64_t)a4;                           \
    register uint64_t __a4 asm("$8") = (uint64_t)a5;                           \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "+r"(__a3)                                      \
                 : "IK"(nr), "r"(__a0), "r"(__a1), "r"(__a2), "r"(__a4)        \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    int64_t res = __v0;                                                        \
    {                                                                          \
      int64_t _sc_err = __a3;                                                  \
      if (_sc_err)                                                             \
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  __HEADER(6)                                                                  \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(                                 \
      __PARAM(1, t1) a1,                                                       \
      __PARAM(2, t2) a2,                                                       \
      __PARAM(3, t3) a3,                                                       \
      __PARAM(4, t4) a4,                                                       \
      __PARAM(5, t5) a5,                                                       \
      __PARAM(6, t6) a6) {                                                     \
    register uint64_t __s0 asm("$16") __attribute__((unused)) = (0);           \
                                                                               \
    register uint64_t __v0 asm("$2");                                          \
    register uint64_t __a0 asm("$4") = (uint64_t)a1;                           \
    register uint64_t __a1 asm("$5") = (uint64_t)a2;                           \
    register uint64_t __a2 asm("$6") = (uint64_t)a3;                           \
    register uint64_t __a3 asm("$7") = (uint64_t)a4;                           \
    register uint64_t __a4 asm("$8") = (uint64_t)a5;                           \
    register uint64_t __a5 asm("$9") = (uint64_t)a6;                           \
                                                                               \
    asm volatile(__SYSCALL_ASM                                                 \
                 : "=r"(__v0), "+r"(__a3)                                      \
                 : "IK"(nr), "r"(__a0), "r"(__a1), "r"(__a2), "r"(__a4),       \
                   "r"(__a5)                                                   \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    int64_t res = __v0;                                                        \
    {                                                                          \
      int64_t _sc_err = __a3;                                                  \
      if (_sc_err)                                                             \
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#include "syscalls.inc.h"

#include "jove_sys.post.h.inc"
#endif /* JOVE_SYS_H */
