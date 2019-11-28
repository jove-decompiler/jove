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

#define ___SYSCALL0(nr, nm)                                                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(void) {                             \
    int32_t retval;                                                            \
                                                                               \
    asm volatile("int $0x80"                                                   \
                 : "=a"(retval)                                                \
                 : "a"(nr)                                                     \
                 : "memory", "cc");                                            \
                                                                               \
    return retval;                                                             \
  }

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1) {                            \
    int32_t retval;                                                            \
                                                                               \
    asm volatile("int $0x80"                                                   \
                 : "=a"(retval)                                                \
                 : "a"(nr),                                                    \
                   "b"(a1)                                                     \
                 : "memory", "cc");                                            \
                                                                               \
    return retval;                                                             \
  }

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2) {                     \
    int32_t retval;                                                            \
                                                                               \
    asm volatile("int $0x80"                                                   \
                 : "=a"(retval)                                                \
                 : "a"(nr),                                                    \
                   "b"(a1),                                                    \
                   "c"(a2)                                                     \
                 : "memory", "cc");                                            \
                                                                               \
    return retval;                                                             \
  }

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3) {              \
    int32_t retval;                                                            \
                                                                               \
    asm volatile("int $0x80"                                                   \
                 : "=a"(retval)                                                \
                 : "a"(nr),                                                    \
                   "b"(a1),                                                    \
                   "c"(a2),                                                    \
                   "d"(a3)                                                     \
                 : "memory", "cc");                                            \
                                                                               \
    return retval;                                                             \
  }

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4) {       \
    int32_t retval;                                                            \
                                                                               \
    asm volatile("int $0x80"                                                   \
                 : "=a"(retval)                                                \
                 : "a"(nr),                                                    \
                   "b"(a1),                                                    \
                   "c"(a2),                                                    \
                   "d"(a3),                                                    \
                   "S"(a4)                                                     \
                 : "memory", "cc");                                            \
                                                                               \
    return retval;                                                             \
  }

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4,         \
                                           t5 a5) {                            \
    int32_t retval;                                                            \
                                                                               \
    asm volatile("int $0x80"                                                   \
                 : "=a"(retval)                                                \
                 : "a"(nr),                                                    \
                   "b"(a1),                                                    \
                   "c"(a2),                                                    \
                   "d"(a3),                                                    \
                   "S"(a4),                                                    \
                   "D"(a5)                                                     \
                 : "memory", "cc");                                            \
                                                                               \
    return retval;                                                             \
  }

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5,  \
                                           t6 a6) {                            \
    int32_t retval;                                                            \
                                                                               \
    register t6 _a6 asm("ebp") = a6;                                           \
                                                                               \
    asm volatile("int $0x80"                                                   \
                 : "=a"(retval)                                                \
                 : "a"(nr),                                                    \
                   "b"(a1),                                                    \
                   "c"(a2),                                                    \
                   "d"(a3),                                                    \
                   "S"(a4),                                                    \
                   "D"(a5),                                                    \
                   "r"(_a6)                                                    \
                 : "memory", "cc");                                            \
                                                                               \
    return retval;                                                             \
  }

#include "syscalls.inc.h"

#undef JOVE_SYS_ATTR
