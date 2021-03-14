#ifndef JOVE_SYS_ATTR
#error
#endif

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
typedef uint64_t u64;
typedef uint32_t u32;
typedef unsigned int qid_t;
typedef int rwf_t;

#define ___SYSCALL0(nr, nm)                                                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(void) {                             \
    register long _ret asm("x0");                                              \
                                                                               \
    register unsigned long _nr asm("x8") = nr;                                 \
                                                                               \
    asm volatile("svc 0\n\t"                                                   \
                 : "=r"(_ret)                                                  \
                 : "r"(_nr)                                                    \
                 : "memory", "cc");                                            \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1) {                            \
    register long _ret asm("x0");                                              \
                                                                               \
    register unsigned long _nr asm("x8") = nr;                                 \
                                                                               \
    register t1 _a1 asm("x0") = a1;                                            \
                                                                               \
    asm volatile("svc 0\n\t"                                                   \
                 : "=r"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1)                                          \
                 : "memory", "cc");                                            \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2) {                     \
    register long _ret asm("x0");                                                                 \
                                                                               \
    register unsigned long _nr asm("x8") = nr;                                 \
                                                                               \
    register t1 _a1 asm("x0") = a1;                                            \
    register t2 _a2 asm("x1") = a2;                                            \
                                                                               \
    asm volatile("svc 0\n\t"                                                   \
                 : "=r"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2)                                \
                 : "memory", "cc");                                            \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3) {              \
    register long _ret asm("x0");                                                                 \
                                                                               \
    register unsigned long _nr asm("x8") = nr;                                 \
                                                                               \
    register t1 _a1 asm("x0") = a1;                                            \
    register t2 _a2 asm("x1") = a2;                                            \
    register t3 _a3 asm("x2") = a3;                                            \
                                                                               \
    asm volatile("svc 0\n\t"                                                   \
                 : "=r"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2), "r"(_a3)                      \
                 : "memory", "cc");                                            \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4) {       \
    register long _ret asm("x0");                                                                 \
                                                                               \
    register unsigned long _nr asm("x8") = nr;                                 \
                                                                               \
    register t1 _a1 asm("x0") = a1;                                            \
    register t2 _a2 asm("x1") = a2;                                            \
    register t3 _a3 asm("x2") = a3;                                            \
    register t4 _a4 asm("x3") = a4;                                            \
                                                                               \
    asm volatile("svc 0\n\t"                                                   \
                 : "=r"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4)            \
                 : "memory", "cc");                                            \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4,         \
                                           t5 a5) {                            \
    register long _ret asm("x0");                                                                 \
                                                                               \
    register unsigned long _nr asm("x8") = nr;                                 \
                                                                               \
    register t1 _a1 asm("x0") = a1;                                            \
    register t2 _a2 asm("x1") = a2;                                            \
    register t3 _a3 asm("x2") = a3;                                            \
    register t4 _a4 asm("x3") = a4;                                            \
    register t5 _a5 asm("x4") = a5;                                            \
                                                                               \
    asm volatile("svc 0\n\t"                                                   \
                 : "=r"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5)  \
                 : "memory", "cc");                                            \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5,  \
                                           t6 a6) {                            \
    register long _ret asm("x0");                                                                 \
                                                                               \
    register unsigned long _nr asm("x8") = nr;                                 \
                                                                               \
    register t1 _a1 asm("x0") = a1;                                            \
    register t2 _a2 asm("x1") = a2;                                            \
    register t3 _a3 asm("x2") = a3;                                            \
    register t4 _a4 asm("x3") = a4;                                            \
    register t5 _a5 asm("x4") = a5;                                            \
    register t6 _a6 asm("x5") = a6;                                            \
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

#undef JOVE_SYS_ATTR
