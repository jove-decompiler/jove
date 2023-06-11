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
typedef unsigned long old_uid_t;
typedef unsigned long old_gid_t;
typedef uint32_t u32;
typedef unsigned long old_sigset_t;
typedef int32_t s32;
typedef s32 old_time32_t;

#ifndef __user
#define __user
#endif

#define __SYSCALL_CLOBBERS "memory", "cc"

#define ___SYSCALL0(nr, nm)                                                    \
static  JOVE_SYS_ATTR long _jove_sys_##nm(void) {                                    \
    long retval;                                                               \
                                                                               \
    unsigned long _nr = nr;                                                    \
                                                                               \
    asm volatile("int $0x80"                                                   \
                 : "=a"(retval)                                                \
                 : "a"(_nr)                                                    \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    return retval;                                                             \
  }

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
static  JOVE_SYS_ATTR long _jove_sys_##nm(long a1) {                                 \
    long retval;                                                               \
                                                                               \
    unsigned long _nr = nr;                                                    \
                                                                               \
    asm volatile("int $0x80"                                                   \
                 : "=a"(retval)                                                \
                 : "a"(_nr),                                                   \
                   "b"(a1)                                                     \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    return retval;                                                             \
  }

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
static  JOVE_SYS_ATTR long _jove_sys_##nm(long a1, long a2) {                        \
    long retval;                                                               \
                                                                               \
    unsigned long _nr = nr;                                                    \
                                                                               \
    asm volatile("int $0x80"                                                   \
                 : "=a"(retval)                                                \
                 : "a"(_nr),                                                   \
                   "b"(a1),                                                    \
                   "c"(a2)                                                     \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    return retval;                                                             \
  }

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
static  JOVE_SYS_ATTR long _jove_sys_##nm(long a1, long a2, long a3) {               \
    long retval;                                                               \
                                                                               \
    unsigned long _nr = nr;                                                    \
                                                                               \
    asm volatile("int $0x80"                                                   \
                 : "=a"(retval)                                                \
                 : "a"(_nr),                                                   \
                   "b"(a1),                                                    \
                   "c"(a2),                                                    \
                   "d"(a3)                                                     \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    return retval;                                                             \
  }

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
static  JOVE_SYS_ATTR long _jove_sys_##nm(long a1, long a2, long a3,                 \
                                           long a4) {                          \
    long retval;                                                               \
                                                                               \
    unsigned long _nr = nr;                                                    \
                                                                               \
    asm volatile("int $0x80"                                                   \
                 : "=a"(retval)                                                \
                 : "a"(_nr),                                                   \
                   "b"(a1),                                                    \
                   "c"(a2),                                                    \
                   "d"(a3),                                                    \
                   "S"(a4)                                                     \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    return retval;                                                             \
  }

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
static  JOVE_SYS_ATTR long _jove_sys_##nm(long a1, long a2, long a3, long a4,        \
                                           long a5) {                          \
    long retval;                                                               \
                                                                               \
    unsigned long _nr = nr;                                                    \
                                                                               \
    asm volatile("int $0x80"                                                   \
                 : "=a"(retval)                                                \
                 : "a"(_nr),                                                   \
                   "b"(a1),                                                    \
                   "c"(a2),                                                    \
                   "d"(a3),                                                    \
                   "S"(a4),                                                    \
                   "D"(a5)                                                     \
                 : __SYSCALL_CLOBBERS);                                        \
                                                                               \
    return retval;                                                             \
  }

//
// we can't do system calls requiring six arguments with inline assembly. this
// is because the sixth argument is in ebp.
//
#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
static  JOVE_SYS_ATTR __attribute__((naked)) long _jove_sys_##nm(                    \
      long a1, long a2, long a3, long a4, long a5, long a6) {                  \
    asm volatile("pushl %%ebp\n"                                               \
                 "pushl %%ebx\n"                                               \
                 "pushl %%edi\n"                                               \
                 "pushl %%esi\n"                                               \
                                                                               \
                 "movl 0x14(%%esp), %%ebx\n"                                   \
                 "movl 0x18(%%esp), %%ecx\n"                                   \
                 "movl 0x1c(%%esp), %%edx\n"                                   \
                 "movl 0x20(%%esp), %%esi\n"                                   \
                 "movl 0x24(%%esp), %%edi\n"                                   \
                 "movl 0x28(%%esp), %%ebp\n"                                   \
                                                                               \
                 "movl $" #nr ",%%eax\n"                                       \
                                                                               \
                 "int $0x80\n"                                                 \
                                                                               \
                 "popl %%esi\n"                                                \
                 "popl %%edi\n"                                                \
                 "popl %%ebx\n"                                                \
                 "popl %%ebp\n"                                                \
                                                                               \
                 "ret\n"                                                       \
                 : /* OutputOperands */                                        \
                 : /* InputOperands */                                         \
                 : /* Clobbers */);                                            \
  }

#include "syscalls.inc.h"

#undef JOVE_SYS_ATTR
