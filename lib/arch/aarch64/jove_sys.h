#ifndef JOVE_SYS_H
#define JOVE_SYS_H

#include "jove_sys.pre.h.inc"

#if 0
#include <sys/quota.h>
//#include <xfs/xqm.h> /* for XFS quotas */
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
//#include <sys/capability.h>
#include <sys/quota.h>
#include <sys/epoll.h>
#include <sched.h>
#include <linux/aio_abi.h>
#include <mqueue.h>
//#include <keyutils.h>
#include <linux/bpf.h>

#ifndef __user
#define __user
#endif

typedef unsigned long cap_user_data_t; /* XXX */
typedef unsigned long cap_user_header_t; /* XXX */
typedef unsigned long key_serial_t; /* XXX */
typedef unsigned int qid_t;
typedef int rwf_t;
typedef uint32_t u32;
#endif

#define ___SYSCALL0(nr, nm)                                                    \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(void) {                          \
    register int64_t _ret asm("x0");                                           \
                                                                               \
    register uint64_t _nr asm("x8") = nr;                                      \
                                                                               \
    asm volatile("svc 0\n\t" : "=r"(_ret) : "r"(_nr) : "memory", "cc");        \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL1(nr, nm, t1, a1)                                           \
  __HEADER(1)                                                                  \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(__PARAM(1, t1) a1) {                 \
    register int64_t _ret asm("x0");                                           \
                                                                               \
    register uint64_t _nr asm("x8") = nr;                                      \
                                                                               \
    register uint64_t _a1 asm("x0") = (int64_t)a1;                              \
                                                                               \
    asm volatile("svc 0\n\t"                                                   \
                 : "=r"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1)                                          \
                 : "memory", "cc");                                            \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                  \
  __HEADER(2)                                                                  \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(                                 \
      __PARAM(1, t1) a1,                                                             \
      __PARAM(2, t2) a2) {                                                           \
    register int64_t _ret asm("x0");                                           \
                                                                               \
    register uint64_t _nr asm("x8") = nr;                                      \
                                                                               \
    register uint64_t _a1 asm("x0") = (uint64_t)a1;                              \
    register uint64_t _a2 asm("x1") = (uint64_t)a2;                              \
                                                                               \
    asm volatile("svc 0\n\t"                                                   \
                 : "=r"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2)                                \
                 : "memory", "cc");                                            \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                         \
  __HEADER(3)                                                                  \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(                                 \
      __PARAM(1, t1) a1,                                                             \
      __PARAM(2, t2) a2,                                                             \
      __PARAM(3, t3) a3) {                                                           \
    register int64_t _ret asm("x0");                                           \
                                                                               \
    register uint64_t _nr asm("x8") = nr;                                      \
                                                                               \
    register uint64_t _a1 asm("x0") = (uint64_t)a1;                              \
    register uint64_t _a2 asm("x1") = (uint64_t)a2;                              \
    register uint64_t _a3 asm("x2") = (uint64_t)a3;                              \
                                                                               \
    asm volatile("svc 0\n\t"                                                   \
                 : "=r"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2), "r"(_a3)                      \
                 : "memory", "cc");                                            \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                \
  __HEADER(4)                                                                  \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(                                 \
      __PARAM(1, t1) a1,                                                             \
      __PARAM(2, t2) a2,                                                             \
      __PARAM(3, t3) a3,                                                             \
      __PARAM(4, t4) a4) {                                                           \
    register int64_t _ret asm("x0");                                           \
                                                                               \
    register uint64_t _nr asm("x8") = nr;                                      \
                                                                               \
    register uint64_t _a1 asm("x0") = (uint64_t)a1;                              \
    register uint64_t _a2 asm("x1") = (uint64_t)a2;                              \
    register uint64_t _a3 asm("x2") = (uint64_t)a3;                              \
    register uint64_t _a4 asm("x3") = (uint64_t)a4;                              \
                                                                               \
    asm volatile("svc 0\n\t"                                                   \
                 : "=r"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4)            \
                 : "memory", "cc");                                            \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)       \
  __HEADER(5)                                                                  \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(                                 \
      __PARAM(1, t1) a1,   \
      __PARAM(2, t2) a2,   \
      __PARAM(3, t3) a3,   \
      __PARAM(4, t4) a4,   \
      __PARAM(5, t5) a5) { \
    register int64_t _ret asm("x0");                                           \
                                                                               \
    register uint64_t _nr asm("x8") = nr;                                      \
                                                                               \
    register uint64_t _a1 asm("x0") = (uint64_t)a1;                              \
    register uint64_t _a2 asm("x1") = (uint64_t)a2;                              \
    register uint64_t _a3 asm("x2") = (uint64_t)a3;                              \
    register uint64_t _a4 asm("x3") = (uint64_t)a4;                              \
    register uint64_t _a5 asm("x4") = (uint64_t)a5;                              \
                                                                               \
    asm volatile("svc 0\n\t"                                                   \
                 : "=r"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5)  \
                 : "memory", "cc");                                            \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6) \
  __HEADER(6)                                                                  \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(                                 \
      __PARAM(1, t1) a1,                                                             \
      __PARAM(2, t2) a2,                                                             \
      __PARAM(3, t3) a3,                                                             \
      __PARAM(4, t4) a4,                                                             \
      __PARAM(5, t5) a5,                                                             \
      __PARAM(6, t6) a6) {                                                           \
    register int64_t _ret asm("x0");                                           \
                                                                               \
    register uint64_t _nr asm("x8") = nr;                                      \
                                                                               \
    register uint64_t _a1 asm("x0") = (uint64_t)a1;                              \
    register uint64_t _a2 asm("x1") = (uint64_t)a2;                              \
    register uint64_t _a3 asm("x2") = (uint64_t)a3;                              \
    register uint64_t _a4 asm("x3") = (uint64_t)a4;                              \
    register uint64_t _a5 asm("x4") = (uint64_t)a5;                              \
    register uint64_t _a6 asm("x5") = (uint64_t)a6;                              \
                                                                               \
    asm volatile("svc 0\n\t"                                                   \
                 : "=r"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), \
                   "r"(_a6)                                                    \
                 : "memory", "cc");                                            \
                                                                               \
    return _ret;                                                               \
  }

#include "syscalls.inc.h"

#include "jove_sys.post.h.inc"
#endif /* JOVE_SYS_H */
