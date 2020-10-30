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

typedef uint64_t u64;
typedef uint32_t u32;
typedef unsigned int qid_t;
typedef int rwf_t;
typedef unsigned long old_sigset_t;
typedef int32_t s32;
typedef s32 old_time32_t;

#define __SYSCALL_CLOBBERS "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", \
                           "$14", "$15", "$24", "$25", "hi", "lo", "memory"

#define __SYSCALL_ASM ".set\tnoreorder\n\t" \
                      "li\t%0, %2\n\t" \
                      "syscall\n\t" \
                      ".set\treorder"

#define ___SYSCALL0(nr, nm)                                                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(void) {                             \
    register long __s0 asm("$16") __attribute__((unused)) = (nr);              \
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
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(long a1) {                          \
    register long __s0 asm("$16") __attribute__((unused)) = (nr);              \
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
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(long a1, long a2) {                 \
    register long __s0 asm("$16") __attribute__((unused)) = (nr);              \
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
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(long a1, long a2, long a3) {        \
    register long __s0 asm("$16") __attribute__((unused)) = (nr);              \
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
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(long a1, long a2, long a3,          \
                                           long a4) {                          \
    register long __s0 asm("$16") __attribute__((unused)) = (nr);              \
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
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

/* Standalone MIPS wrappers used for 5, 6, and 7 argument syscalls,
   which require stack arguments.  We rely on the compiler arranging
   wrapper's arguments according to the MIPS o32 function calling
   convention, which is reused by syscalls, except for the syscall
   number passed and the error flag returned (taken care of in the
   wrapper called).  This relieves us from relying on non-guaranteed
   compiler specifics required for the stack arguments to be pushed,
   which would be the case if these syscalls were inlined.  */
union __mips_syscall_return {
  uint64_t val;
  struct {
    uint32_t v0;
    uint32_t v1;
  } reg;
};

static uint64_t __attribute__((noinline))
__attribute__((naked))
__mips_syscall5(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4,
                uint32_t arg5, uint32_t number) {
  asm volatile(".set\tnoreorder\n"
               "lw $v0, 20($sp)\n"
               "syscall\n"
               "move $v1, $a3\n"
               "jr $ra\n"
               "nop\n"
               ".set\treorder");
}

static uint64_t __attribute__((noinline))
__attribute__((naked))
__mips_syscall6(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4,
                uint32_t arg5, uint32_t arg6, uint32_t number) {
  asm volatile(".set\tnoreorder\n"
               "lw $v0, 24($sp)\n"
               "syscall\n"
               "move $v1, $a3\n"
               "jr $ra\n"
               "nop\n"
               ".set\treorder");
}

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  static JOVE_SYS_ATTR long _jove_sys_##nm(long a1, long a2, long a3, long a4, \
                                           long a5) {                          \
    union __mips_syscall_return _sc_ret;                                       \
    _sc_ret.val = __mips_syscall5(a1, a2, a3, a4, a5, nr);                     \
                                                                               \
    long res = _sc_ret.reg.v0;                                                 \
                                                                               \
    {                                                                          \
      long _sc_err = _sc_ret.reg.v1;                                           \
      if (_sc_err)                                                             \
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  static JOVE_SYS_ATTR long _jove_sys_##nm(long a1, long a2, long a3, long a4, \
                                           long a5, long a6) {                 \
    union __mips_syscall_return _sc_ret;                                       \
    _sc_ret.val = __mips_syscall6(a1, a2, a3, a4, a5, a6, nr);                 \
                                                                               \
    long res = _sc_ret.reg.v0;                                                 \
                                                                               \
    {                                                                          \
      long _sc_err = _sc_ret.reg.v1;                                           \
      if (_sc_err)                                                             \
        res = -res;                                                            \
    }                                                                          \
                                                                               \
    return res;                                                                \
  }

#include "syscalls.inc.h"

#undef JOVE_SYS_ATTR
