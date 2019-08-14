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
    long _ret;                                                                 \
                                                                               \
    register unsigned long _nr asm("rax") = nr;                                \
                                                                               \
    asm volatile("syscall\n\t"                                                 \
                 : "=a"(_ret)                                                  \
                 : "r"(_nr)                                                    \
                 : "memory", "cc", "r11", "cx");                               \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1) {                            \
    long _ret;                                                                 \
                                                                               \
    register unsigned long _nr asm("rax") = nr;                                \
                                                                               \
    register t1 _a1 asm("rdi") = a1;                                           \
                                                                               \
    asm volatile("syscall\n\t"                                                 \
                 : "=a"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1)                                          \
                 : "memory", "cc", "r11", "cx");                               \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2) {                     \
    long _ret;                                                                 \
                                                                               \
    register unsigned long _nr asm("rax") = nr;                                \
                                                                               \
    register t1 _a1 asm("rdi") = a1;                                           \
    register t2 _a2 asm("rsi") = a2;                                           \
                                                                               \
    asm volatile("syscall\n\t"                                                 \
                 : "=a"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2)                                \
                 : "memory", "cc", "r11", "cx");                               \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3) {              \
    long _ret;                                                                 \
                                                                               \
    register unsigned long _nr asm("rax") = nr;                                \
                                                                               \
    register t1 _a1 asm("rdi") = a1;                                           \
    register t2 _a2 asm("rsi") = a2;                                           \
    register t3 _a3 asm("rdx") = a3;                                           \
                                                                               \
    asm volatile("syscall\n\t"                                                 \
                 : "=a"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2), "r"(_a3)                      \
                 : "memory", "cc", "r11", "cx");                               \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4) {       \
    long _ret;                                                                 \
                                                                               \
    register unsigned long _nr asm("rax") = nr;                                \
                                                                               \
    register t1 _a1 asm("rdi") = a1;                                           \
    register t2 _a2 asm("rsi") = a2;                                           \
    register t3 _a3 asm("rdx") = a3;                                           \
    register t4 _a4 asm("r10") = a4;                                           \
                                                                               \
    asm volatile("syscall\n\t"                                                 \
                 : "=a"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4)            \
                 : "memory", "cc", "r11", "cx");                               \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4,         \
                                           t5 a5) {                            \
    long _ret;                                                                 \
                                                                               \
    register unsigned long _nr asm("rax") = nr;                                \
                                                                               \
    register t1 _a1 asm("rdi") = a1;                                           \
    register t2 _a2 asm("rsi") = a2;                                           \
    register t3 _a3 asm("rdx") = a3;                                           \
    register t4 _a4 asm("r10") = a4;                                           \
    register t5 _a5 asm("r8") = a5;                                            \
                                                                               \
    asm volatile("syscall\n\t"                                                 \
                 : "=a"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5)  \
                 : "memory", "cc", "r11", "cx");                               \
                                                                               \
    return _ret;                                                               \
  }

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5,  \
                                           t6 a6) {                            \
    long _ret;                                                                 \
                                                                               \
    register unsigned long _nr asm("rax") = nr;                                \
                                                                               \
    register t1 _a1 asm("rdi") = a1;                                           \
    register t2 _a2 asm("rsi") = a2;                                           \
    register t3 _a3 asm("rdx") = a3;                                           \
    register t4 _a4 asm("r10") = a4;                                           \
    register t5 _a5 asm("r8") = a5;                                            \
    register t6 _a6 asm("r9") = a6;                                            \
                                                                               \
    asm volatile("syscall\n\t"                                                 \
                 : "=a"(_ret)                                                  \
                 : "r"(_nr), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), \
                   "r"(_a6)                                                    \
                 : "memory", "cc", "r11", "cx");                               \
                                                                               \
    return _ret;                                                               \
  }

#include "syscalls.inc.h"

#undef JOVE_SYS_ATTR
