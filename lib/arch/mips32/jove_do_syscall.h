  if (exception != 17 /* EXCP_SYSCALL */) {
    __builtin_trap();
    __builtin_unreachable();
  }

void do_syscall(CPUMIPSState *);

  do_syscall(env);
} /* see qemu/target/mips/tcg/exception.c */

#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>

static const char *syscall_names[] = {
#define ___SYSCALL(nr, nm) [nr] = #nm,
#include "syscalls.inc.h"
};

#define JOVE_CRASH_MODE 'a'

#include "jove.macros.h"
#include "jove.constants.h"

#define JOVE_SYS_ATTR _INL _UNUSED

#include "jove.util.c"

#ifdef JOVE_DFSAN

#define SYSEXIT(nm) __dfs_sys_exit_##nm
#define SYSENTR(nm) __dfs_sys_entr_##nm

//
// declare dfsan syscall hooks
//
#define ___SYSCALL0(nr, nm)                                                    \
  void SYSEXIT(nm)(long sysret);                                               \
  _HIDDEN typeof(SYSEXIT(nm)) *SYSEXIT(nm##_clunk) = SYSEXIT(nm);

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  void SYSEXIT(nm)(long sysret, t1 a1);                                        \
  _HIDDEN typeof(SYSEXIT(nm)) *SYSEXIT(nm##_clunk) = SYSEXIT(nm);

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  void SYSEXIT(nm)(long sysret, t1 a1, t2 a2);                                 \
  _HIDDEN typeof(SYSEXIT(nm)) *SYSEXIT(nm##_clunk) = SYSEXIT(nm);

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  void SYSEXIT(nm)(long sysret, t1 a1, t2 a2, t3 a3);                          \
  _HIDDEN typeof(SYSEXIT(nm)) *SYSEXIT(nm##_clunk) = SYSEXIT(nm);

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  void SYSEXIT(nm)(long sysret, t1 a1, t2 a2, t3 a3, t4 a4);                   \
  _HIDDEN typeof(SYSEXIT(nm)) *SYSEXIT(nm##_clunk) = SYSEXIT(nm);

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  void SYSEXIT(nm)(long sysret, t1 a1, t2 a2, t3 a3, t4 a4, t5 a5);            \
  _HIDDEN typeof(SYSEXIT(nm)) *SYSEXIT(nm##_clunk) = SYSEXIT(nm);

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  void SYSEXIT(nm)(long sysret, t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6);     \
  _HIDDEN typeof(SYSEXIT(nm)) *SYSEXIT(nm##_clunk) = SYSEXIT(nm);

#define ___DFSAN
#define ___DFSAN_SYSEXITS
#include "syscalls.inc.h"
#undef ___DFSAN_SYSEXITS
#undef ___DFSAN

#define ___SYSCALL0(nr, nm)                                                    \
  void SYSENTR(nm)();                                                          \
  _HIDDEN typeof(SYSENTR(nm)) *SYSENTR(nm##_clunk) = SYSENTR(nm);

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  void SYSENTR(nm)(t1 a1);                                                     \
  _HIDDEN typeof(SYSENTR(nm)) *SYSENTR(nm##_clunk) = SYSENTR(nm);

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  void SYSENTR(nm)(t1 a1, t2 a2);                                              \
  _HIDDEN typeof(SYSENTR(nm)) *SYSENTR(nm##_clunk) = SYSENTR(nm);

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  void SYSENTR(nm)(t1 a1, t2 a2, t3 a3);                                       \
  _HIDDEN typeof(SYSENTR(nm)) *SYSENTR(nm##_clunk) = SYSENTR(nm);

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  void SYSENTR(nm)(t1 a1, t2 a2, t3 a3, t4 a4);                                \
  _HIDDEN typeof(SYSENTR(nm)) *SYSENTR(nm##_clunk) = SYSENTR(nm);

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  void SYSENTR(nm)(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5);                         \
  _HIDDEN typeof(SYSENTR(nm)) *SYSENTR(nm##_clunk) = SYSENTR(nm);

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  void SYSENTR(nm)(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6);                  \
  _HIDDEN typeof(SYSENTR(nm)) *SYSENTR(nm##_clunk) = SYSENTR(nm);

#define ___DFSAN
#define ___DFSAN_SYSENTRS
#include "syscalls.inc.h"
#undef ___DFSAN_SYSENTRS
#undef ___DFSAN

#endif /* JOVE_DFSAN */

void do_syscall(CPUMIPSState *env) {
  unsigned long sysnum = env->active_tc.gpr[2];

#define env_sp env->active_tc.gpr[29]

#define env_a1 env->active_tc.gpr[4]
#define env_a2 env->active_tc.gpr[5]
#define env_a3 env->active_tc.gpr[6]
#define env_a4 env->active_tc.gpr[7]
#define env_a5 (*((uint32_t *)(env_sp + 16)))
#define env_a6 (*((uint32_t *)(env_sp + 20)))

  long _a1 = env_a1;
  long _a2 = env_a2;
  long _a3 = env_a3;
  long _a4 = env_a4;
  long _a5 = env_a5;
  long _a6 = env_a6;

#undef env_a1
#undef env_a2
#undef env_a3
#undef env_a4
#undef env_a5
#undef env_a6

#if 0
  if (sysnum < ARRAY_SIZE(syscall_names)) {
    const char *nm = syscall_names[sysnum];
    if (nm) {
      char buff[2048];
      buff[0] = '\0';

      //
      // print syscall name
      //
      _strcat(buff, __ANSI_GREEN);
      _strcat(buff, nm);
      _strcat(buff, __ANSI_NORMAL_COLOR);

      //
      // print syscall arguments
      //
      if (sysnum == 4039 /* mkdir */ && _a1) {
        _strcat(buff, "(\"");
        _strcat(buff, (const char *)_a1);
        _strcat(buff, "\")");
      }

      if (sysnum == 4005 /* open */ && _a1) {
        _strcat(buff, "(\"");
        _strcat(buff, (const char *)_a1);
        _strcat(buff, "\")");
      }

      if (sysnum == 4288 /* openat */ && _a2) {
        _strcat(buff, "(\"");
        _strcat(buff, (const char *)_a2);
        _strcat(buff, "\")");
      }

      if (sysnum == 4039 /* mkdir */ && _a1) {
        _strcat(buff, "(\"");
        _strcat(buff, (const char *)_a1);
        _strcat(buff, "\")");
      }

      if (sysnum == 4040 /* rmdir */ && _a1) {
        _strcat(buff, "(\"");
        _strcat(buff, (const char *)_a1);
        _strcat(buff, "\")");
      }

      if (sysnum == 4033 /* access */ && _a1) {
        _strcat(buff, "(\"");
        _strcat(buff, (const char *)_a1);
        _strcat(buff, "\")");
      }

      if (sysnum == 4006 /* close */ ||
          sysnum == 4001 /* exit */ ||
          sysnum == 4246 /* exit_group */) {
        _strcat(buff, "(");

        {
          char buf[256];
          uint_to_string(_a1, buf);

          _strcat(buff, buf);
        }

        _strcat(buff, ")");
      }

      if (sysnum == 4011 /* execve */ && _a1) {
        _strcat(buff, "(\"");
        _strcat(buff, (const char *)_a1);
        _strcat(buff, "\" ");

        {
          const char **argv = (const char **)_a2;
          while (*argv) {
            _strcat(buff, *argv);
            ++argv;

            _strcat(buff, " ");
          }
        }

        {
          const char **envp = (const char **)_a3;
          while (*envp) {
            _strcat(buff, *envp);
            ++envp;

            _strcat(buff, " ");
          }
        }

        _strcat(buff, "\")");
      }

      if (sysnum == 4356 /* execveat */ && _a2) {
        _strcat(buff, "(\"");
        _strcat(buff, (const char *)_a2);
        _strcat(buff, "\" ");

        {
          const char **argv = (const char **)_a3;
          while (*argv) {
            _strcat(buff, *argv);
            ++argv;

            _strcat(buff, " ");
          }
        }

        {
          const char **envp = (const char **)_a4;
          while (*envp) {
            _strcat(buff, *envp);
            ++envp;

            _strcat(buff, " ");
          }
        }

        _strcat(buff, "\")");
      }

      _strcat(buff, "\n");

      _jove_sys_write(2, buff, _strlen(buff));
    }
  }
#endif

#if 0
  if (sysnum == 4006 /* close */ && (_a1 == 0 || _a1 == 1)) {
    //
    // fake sucessful return
    //
    env->active_tc.gpr[7] = 0;
    env->active_tc.gpr[2] = 0;
    return;
  }
#endif

#if 0
  switch (sysnum) {
    case 4166: /* nanosleep_time32 */
    case 4265: /* clock_nanosleep_time32 */
    case 4407: /* clock_nanosleep */
      //
      // fake successful return
      //
      env->active_tc.gpr[7] = 0;
      env->active_tc.gpr[2] = 0;
      return;

    default:
      break;
  }
#endif

#ifdef JOVE_DFSAN
  //
  // call sysenter procedure
  //
  switch (sysnum) {
#define ___SYSCALL0(nr, nm)                                                    \
  case nr:                                                                     \
    SYSENTR(nm##_clunk)();                                                     \
    break;
#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  case nr:                                                                     \
    SYSENTR(nm##_clunk)((t1)_a1);                                              \
    break;
#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  case nr:                                                                     \
    SYSENTR(nm##_clunk)((t1)_a1, (t2)_a2);                                     \
    break;
#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  case nr:                                                                     \
    SYSENTR(nm##_clunk)((t1)_a1, (t2)_a2, (t3)_a3);                            \
    break;
#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  case nr:                                                                     \
    SYSENTR(nm##_clunk)((t1)_a1, (t2)_a2, (t3)_a3, (t4)_a4);                   \
    break;
#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  case nr:                                                                     \
    SYSENTR(nm##_clunk)((t1)_a1, (t2)_a2, (t3)_a3, (t4)_a4, (t5)_a5);          \
    break;
#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  case nr:                                                                     \
    SYSENTR(nm##_clunk)((t1)_a1, (t2)_a2, (t3)_a3, (t4)_a4, (t5)_a5, (t6)_a6); \
    break;

#define ___DFSAN
#define ___DFSAN_SYSENTRS
#include "syscalls.inc.h"
#undef ___DFSAN_SYSENTRS
#undef ___DFSAN

  default:
    break;
  }

#endif

  //
  // hacks
  //
#if 0
  if (sysnum == 174 /* rt_sigaction */) {
    unsigned long *act = (unsigned long *)env_a2;
    act[2] = (unsigned long)_jove_restore_rt;
  }
#endif

  //
  // perform the call
  //

  /* For historic reasons the pipe(2) syscall on MIPS returns results in
   * registers $v0 and $v1 */
  if (sysnum == 4042 /* sysm_pipe */) {
    register long r7 asm("$7");
    register long r2 asm("$2");
    register long r3 asm("$3");
    asm volatile("addu $2,$0,%3 ; syscall"
                 : "=&r"(r2), "=r"(r7), "=r"(r3)
                 : "ir"(4042), "0"(r2)
                 : __SYSCALL_CLOBBERS, "$8", "$9", "$10");
    env->active_tc.gpr[7] = r7;
    env->active_tc.gpr[2] = r2;
    env->active_tc.gpr[3] = r3;
    return;
  }

  switch (sysnum) {
#define ___SYSCALL0(nr, nm)                                                    \
  case nr: {                                                                   \
    register long r7 asm("$7");                                                \
    register long r2 asm("$2");                                                \
    asm volatile("addu $2,$0,%2 ; syscall"                                     \
                 : "=&r"(r2), "=r"(r7)                                         \
                 : "ir"(nr), "0"(r2)                                           \
                 : __SYSCALL_CLOBBERS, "$8", "$9", "$10");                     \
    env->active_tc.gpr[7] = r7;                                                \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  case nr: {                                                                   \
    register long r4 asm("$4") = _a1;                                          \
    register long r7 asm("$7");                                                \
    register long r2 asm("$2");                                                \
    asm volatile("addu $2,$0,%2 ; syscall"                                     \
                 : "=&r"(r2), "=r"(r7)                                         \
                 : "ir"(nr), "0"(r2), "r"(r4)                                  \
                 : __SYSCALL_CLOBBERS, "$8", "$9", "$10");                     \
    env->active_tc.gpr[7] = r7;                                                \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  case nr: {                                                                   \
    register long r4 asm("$4") = _a1;                                          \
    register long r5 asm("$5") = _a2;                                          \
    register long r7 asm("$7");                                                \
    register long r2 asm("$2");                                                \
    asm volatile("addu $2,$0,%2 ; syscall"                                     \
                 : "=&r"(r2), "=r"(r7)                                         \
                 : "ir"(nr), "0"(r2), "r"(r4), "r"(r5)                         \
                 : __SYSCALL_CLOBBERS, "$8", "$9", "$10");                     \
    env->active_tc.gpr[7] = r7;                                                \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  case nr: {                                                                   \
    register long r4 asm("$4") = _a1;                                          \
    register long r5 asm("$5") = _a2;                                          \
    register long r6 asm("$6") = _a3;                                          \
    register long r7 asm("$7");                                                \
    register long r2 asm("$2");                                                \
    asm volatile("addu $2,$0,%2 ; syscall"                                     \
                 : "=&r"(r2), "=r"(r7)                                         \
                 : "ir"(nr), "0"(r2), "r"(r4), "r"(r5), "r"(r6)                \
                 : __SYSCALL_CLOBBERS, "$8", "$9", "$10");                     \
    env->active_tc.gpr[7] = r7;                                                \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  case nr: {                                                                   \
    register long r4 asm("$4") = _a1;                                          \
    register long r5 asm("$5") = _a2;                                          \
    register long r6 asm("$6") = _a3;                                          \
    register long r7 asm("$7") = _a4;                                          \
    register long r2 asm("$2");                                                \
    asm volatile("addu $2,$0,%2 ; syscall"                                     \
                 : "=&r"(r2), "+r"(r7)                                         \
                 : "ir"(nr), "0"(r2), "r"(r4), "r"(r5), "r"(r6)                \
                 : __SYSCALL_CLOBBERS, "$8", "$9", "$10");                     \
    env->active_tc.gpr[7] = r7;                                                \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  case nr: {                                                                   \
    register long r4 asm("$4") = _a1;                                          \
    register long r5 asm("$5") = _a2;                                          \
    register long r6 asm("$6") = _a3;                                          \
    register long r7 asm("$7") = _a4;                                          \
    register long r8 asm("$8") = _a5;                                          \
    register long r2 asm("$2");                                                \
    asm volatile("subu $sp,$sp,32 ; sw $8,16($sp) ; "                          \
                 "addu $2,$0,%3 ; syscall ;"                                   \
                 "addu $sp,$sp,32"                                             \
                 : "=&r"(r2), "+r"(r7), "+r"(r8)                               \
                 : "ir"(nr), "0"(r2), "r"(r4), "r"(r5), "r"(r6)                \
                 : __SYSCALL_CLOBBERS, "$9", "$10");                           \
    env->active_tc.gpr[7] = r7;                                                \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  case nr: {                                                                   \
    register long r4 asm("$4") = _a1;                                          \
    register long r5 asm("$5") = _a2;                                          \
    register long r6 asm("$6") = _a3;                                          \
    register long r7 asm("$7") = _a4;                                          \
    register long r8 asm("$8") = _a5;                                          \
    register long r9 asm("$9") = _a6;                                          \
    register long r2 asm("$2");                                                \
    asm volatile("subu $sp,$sp,32 ; sw $8,16($sp) ; sw $9,20($sp) ; "          \
                 "addu $2,$0,%4 ; syscall ;"                                   \
                 "addu $sp,$sp,32"                                             \
                 : "=&r"(r2), "+r"(r7), "+r"(r8), "+r"(r9)                     \
                 : "ir"(nr), "0"(r2), "r"(r4), "r"(r5), "r"(r6)                \
                 : __SYSCALL_CLOBBERS, "$10");                                 \
    env->active_tc.gpr[7] = r7;                                                \
    env->active_tc.gpr[2] = r2;                                                \
    break;                                                                     \
  }

#include "syscalls.inc.h"

  default:
    __builtin_trap();
    __builtin_unreachable();
  }

#ifdef JOVE_DFSAN
  long sysret;
  {
    long r7 = env->active_tc.gpr[7];
    long r2 = env->active_tc.gpr[2];

    sysret = r7 && r2 > 0 ? -r2 : r2;
  }

  //
  // call sysexit procedures
  //
  switch (sysnum) {
#define ___SYSCALL0(nr, nm)                                                    \
  case nr:                                                                     \
    SYSEXIT(nm##_clunk)(sysret);                                               \
    break;
#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  case nr:                                                                     \
    SYSEXIT(nm##_clunk)(sysret, (t1)_a1);                                      \
    break;
#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  case nr:                                                                     \
    SYSEXIT(nm##_clunk)(sysret, (t1)_a1, (t2)_a2);                             \
    break;
#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  case nr:                                                                     \
    SYSEXIT(nm##_clunk)(sysret, (t1)_a1, (t2)_a2, (t3)_a3);                    \
    break;
#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  case nr:                                                                     \
    SYSEXIT(nm##_clunk)(sysret, (t1)_a1, (t2)_a2, (t3)_a3, (t4)_a4);           \
    break;
#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  case nr:                                                                     \
    SYSEXIT(nm##_clunk)(sysret, (t1)_a1, (t2)_a2, (t3)_a3, (t4)_a4, (t5)_a5);  \
    break;
#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  case nr:                                                                     \
    SYSEXIT(nm##_clunk)(sysret, (t1)_a1, (t2)_a2, (t3)_a3, (t4)_a4, (t5)_a5, (t6)_a6); \
    break;

#define ___DFSAN
#define ___DFSAN_SYSEXITS
#include "syscalls.inc.h"
#undef ___DFSAN_SYSEXITS
#undef ___DFSAN

  default:
    break;
  }

#endif /* JOVE_DFSAN */
}

static void ____(void) { /* see qemu/target/mips/tcg/exception.c */
