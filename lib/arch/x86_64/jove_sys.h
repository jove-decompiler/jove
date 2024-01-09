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
#include <linux/capability.h>
#include <sys/quota.h>
#include <sys/epoll.h>
#include <sched.h>
#include <linux/aio_abi.h>
#include <mqueue.h>
//#include <keyutils.h>
#include <linux/bpf.h>

typedef unsigned long key_serial_t;
#ifndef __user
#define __user
#endif

#define __SYSCALL_CLOBBERS "memory", "cc", "r11", "rcx"

#define ___SYSCALL0(nr, nm)                                                    \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(void) {                          \
    int64_t _ret;                                                              \
                                                                               \
    uint64_t _nr = nr;                                                         \
                                                                               \
    asm volatile("syscall\n"                                                   \
                 : "=a"(_ret)                                                  \
                 : "a"(_nr)                                                    \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(t1 a1) {                         \
    int64_t _ret;                                                              \
                                                                               \
    uint64_t _nr = nr;                                                         \
                                                                               \
    int64_t _a1 = (int64_t)a1;                                                 \
                                                                               \
    asm volatile("syscall\n"                                                   \
                 : "=a"(_ret)                                                  \
                 : "a"(_nr), "D"(_a1)                                          \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(t1 a1, t2 a2) {                  \
    int64_t _ret;                                                              \
                                                                               \
    uint64_t _nr = nr;                                                         \
                                                                               \
    int64_t _a1 = (int64_t)a1;                                                 \
    int64_t _a2 = (int64_t)a2;                                                 \
                                                                               \
    asm volatile("syscall\n"                                                   \
                 : "=a"(_ret)                                                  \
                 : "a"(_nr), "D"(_a1), "S"(_a2)                                \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(t1 a1, t2 a2, t3 a3) {           \
    int64_t _ret;                                                              \
                                                                               \
    uint64_t _nr = nr;                                                         \
                                                                               \
    int64_t _a1 = (int64_t)a1;                                                 \
    int64_t _a2 = (int64_t)a2;                                                 \
    int64_t _a3 = (int64_t)a3;                                                 \
                                                                               \
    asm volatile("syscall\n"                                                   \
                 : "=a"(_ret)                                                  \
                 : "a"(_nr), "D"(_a1), "S"(_a2), "d"(_a3)                      \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4) {    \
    int64_t _ret;                                                              \
                                                                               \
    uint64_t _nr = nr;                                                         \
                                                                               \
    int64_t _a1 = (int64_t)a1;                                                 \
    int64_t _a2 = (int64_t)a2;                                                 \
    int64_t _a3 = (int64_t)a3;                                                 \
    int64_t _a4 = (int64_t)a4;                                                 \
                                                                               \
    asm volatile("movq %5, %%r10\n"                                            \
                 "syscall\n"                                                   \
                 : "=a"(_ret)                                                  \
                 : "a"(_nr), "D"(_a1), "S"(_a2), "d"(_a3), "r"(_a4)            \
                 : __SYSCALL_CLOBBERS, "r10");                                 \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4,      \
                                              t5 a5) {                         \
    int64_t _ret;                                                              \
                                                                               \
    uint64_t _nr = nr;                                                         \
                                                                               \
    int64_t _a1 = (int64_t)a1;                                                 \
    int64_t _a2 = (int64_t)a2;                                                 \
    int64_t _a3 = (int64_t)a3;                                                 \
    int64_t _a4 = (int64_t)a4;                                                 \
    int64_t _a5 = (int64_t)a5;                                                 \
                                                                               \
    asm volatile("movq %5, %%r10\n"                                            \
                 "movq %6, %%r8\n"                                             \
                 "syscall\n"                                                   \
                 : "=a"(_ret)                                                  \
                 : "a"(_nr), "D"(_a1), "S"(_a2), "d"(_a3), "r"(_a4), "r"(_a5)  \
                 : __SYSCALL_CLOBBERS, "r10", "r8");                           \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  static JOVE_SYS_ATTR int64_t _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4,      \
                                              t5 a5, t6 a6) {                  \
    int64_t _ret;                                                              \
                                                                               \
    uint64_t _nr = nr;                                                         \
                                                                               \
    int64_t _a1 = (int64_t)a1;                                                 \
    int64_t _a2 = (int64_t)a2;                                                 \
    int64_t _a3 = (int64_t)a3;                                                 \
    int64_t _a4 = (int64_t)a4;                                                 \
    int64_t _a5 = (int64_t)a5;                                                 \
    int64_t _a6 = (int64_t)a6;                                                 \
                                                                               \
    asm volatile("movq %5, %%r10\n"                                            \
                 "movq %6, %%r8\n"                                             \
                 "movq %7, %%r9\n"                                             \
                 "syscall\n"                                                   \
                 : "=a"(_ret)                                                  \
                 : "a"(_nr), "D"(_a1), "S"(_a2), "d"(_a3), "r"(_a4), "r"(_a5), \
                   "r"(_a6)                                                    \
                 : __SYSCALL_CLOBBERS, "r10", "r8", "r9");                     \
                                                                               \
    return _ret;                                                               \
  }

#include "syscalls.inc.h"

#undef JOVE_SYS_ATTR
