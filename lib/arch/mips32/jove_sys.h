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
//#include <sys/socket.h>
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
#include <mqueue.h>
//#include <keyutils.h>
//#include <linux/bpf.h>

#ifndef __user
#define __user
#endif

typedef unsigned long key_serial_t;
typedef int32_t __s32;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef unsigned long aio_context_t;
typedef unsigned long cap_user_data_t;
typedef unsigned long cap_user_header_t;
typedef uint64_t u64;
typedef uint32_t u32;
typedef unsigned int qid_t;
typedef int rwf_t;
typedef unsigned long old_sigset_t;
typedef int32_t s32;
typedef s32 old_time32_t;

#if __mips_isa_rev >= 6
#define __SYSCALL_CLOBBERS \
	"$1", "$3", "$11", "$12", "$13", \
	"$14", "$15", "$24", "$25", "memory"
#else
#define __SYSCALL_CLOBBERS \
	"$1", "$3", "$11", "$12", "$13", \
	"$14", "$15", "$24", "$25", "hi", "lo", "memory"
#endif

#define ___SYSCALL0(nr, nm)                                                    \
  static JOVE_SYS_ATTR int32_t _jove_sys_##nm(void) {                          \
    register int32_t r7 asm("$7");                                             \
    register int32_t r2 asm("$2");                                             \
    asm volatile("addu $2,$0,%2 ; syscall"                                     \
                 : "=&r"(r2), "=r"(r7)                                         \
                 : "ir"(nr), "0"(r2)                                           \
                 : __SYSCALL_CLOBBERS, "$8", "$9", "$10");                     \
    return r7 && r2 > 0 ? -r2 : r2;                                            \
  }

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  static JOVE_SYS_ATTR int32_t _jove_sys_##nm(t1 a1) {                         \
    register int32_t r4 asm("$4") = (int32_t)a1;                               \
    register int32_t r7 asm("$7");                                             \
    register int32_t r2 asm("$2");                                             \
    asm volatile("addu $2,$0,%2 ; syscall"                                     \
                 : "=&r"(r2), "=r"(r7)                                         \
                 : "ir"(nr), "0"(r2), "r"(r4)                                  \
                 : __SYSCALL_CLOBBERS, "$8", "$9", "$10");                     \
    return r7 && r2 > 0 ? -r2 : r2;                                            \
  }

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  static JOVE_SYS_ATTR int32_t _jove_sys_##nm(t1 a1, t2 a2) {                  \
    register int32_t r4 asm("$4") = (int32_t)a1;                               \
    register int32_t r5 asm("$5") = (int32_t)a2;                               \
    register int32_t r7 asm("$7");                                             \
    register int32_t r2 asm("$2");                                             \
    asm volatile("addu $2,$0,%2 ; syscall"                                     \
                 : "=&r"(r2), "=r"(r7)                                         \
                 : "ir"(nr), "0"(r2), "r"(r4), "r"(r5)                         \
                 : __SYSCALL_CLOBBERS, "$8", "$9", "$10");                     \
    return r7 && r2 > 0 ? -r2 : r2;                                            \
  }

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  static JOVE_SYS_ATTR int32_t _jove_sys_##nm(t1 a1, t2 a2, t3 a3) {           \
    register int32_t r4 asm("$4") = (int32_t)a1;                               \
    register int32_t r5 asm("$5") = (int32_t)a2;                               \
    register int32_t r6 asm("$6") = (int32_t)a3;                               \
    register int32_t r7 asm("$7");                                             \
    register int32_t r2 asm("$2");                                             \
    asm volatile("addu $2,$0,%2 ; syscall"                                     \
                 : "=&r"(r2), "=r"(r7)                                         \
                 : "ir"(nr), "0"(r2), "r"(r4), "r"(r5), "r"(r6)                \
                 : __SYSCALL_CLOBBERS, "$8", "$9", "$10");                     \
    return r7 && r2 > 0 ? -r2 : r2;                                            \
  }

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  static JOVE_SYS_ATTR int32_t _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4) {    \
    register int32_t r4 asm("$4") = (int32_t)a1;                               \
    register int32_t r5 asm("$5") = (int32_t)a2;                               \
    register int32_t r6 asm("$6") = (int32_t)a3;                               \
    register int32_t r7 asm("$7") = (int32_t)a4;                               \
    register int32_t r2 asm("$2");                                             \
    asm volatile("addu $2,$0,%2 ; syscall"                                     \
                 : "=&r"(r2), "+r"(r7)                                         \
                 : "ir"(nr), "0"(r2), "r"(r4), "r"(r5), "r"(r6)                \
                 : __SYSCALL_CLOBBERS, "$8", "$9", "$10");                     \
    return r7 && r2 > 0 ? -r2 : r2;                                            \
  }

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  static JOVE_SYS_ATTR int32_t _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4,      \
                                              t5 a5) {                         \
    register int32_t r4 asm("$4") = (int32_t)a1;                               \
    register int32_t r5 asm("$5") = (int32_t)a2;                               \
    register int32_t r6 asm("$6") = (int32_t)a3;                               \
    register int32_t r7 asm("$7") = (int32_t)a4;                               \
    register int32_t r8 asm("$8") = (int32_t)a5;                               \
    register int32_t r2 asm("$2");                                             \
    asm volatile("subu $sp,$sp,32 ; sw $8,16($sp) ; "                          \
                 "addu $2,$0,%3 ; syscall ;"                                   \
                 "addu $sp,$sp,32"                                             \
                 : "=&r"(r2), "+r"(r7), "+r"(r8)                               \
                 : "ir"(nr), "0"(r2), "r"(r4), "r"(r5), "r"(r6)                \
                 : __SYSCALL_CLOBBERS, "$9", "$10");                           \
    return r7 && r2 > 0 ? -r2 : r2;                                            \
  }

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  static JOVE_SYS_ATTR int32_t _jove_sys_##nm(t1 a1, t2 a2, t3 a3, t4 a4,      \
                                              t5 a5, t6 a6) {                  \
    register int32_t r4 asm("$4") = (int32_t)a1;                               \
    register int32_t r5 asm("$5") = (int32_t)a2;                               \
    register int32_t r6 asm("$6") = (int32_t)a3;                               \
    register int32_t r7 asm("$7") = (int32_t)a4;                               \
    register int32_t r8 asm("$8") = (int32_t)a5;                               \
    register int32_t r9 asm("$9") = (int32_t)a6;                               \
    register int32_t r2 asm("$2");                                             \
    asm volatile("subu $sp,$sp,32 ; sw $8,16($sp) ; sw $9,20($sp) ; "          \
                 "addu $2,$0,%4 ; syscall ;"                                   \
                 "addu $sp,$sp,32"                                             \
                 : "=&r"(r2), "+r"(r7), "+r"(r8), "+r"(r9)                     \
                 : "ir"(nr), "0"(r2), "r"(r4), "r"(r5), "r"(r6)                \
                 : __SYSCALL_CLOBBERS, "$10");                                 \
    return r7 && r2 > 0 ? -r2 : r2;                                            \
  }

#include "syscalls.inc.h"

#undef JOVE_SYS_ATTR
