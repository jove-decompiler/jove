__attribute__((always_inline,flatten)) void handle(CPUARMState *, uint32_t excp);

  handle(env, excp);
} /* see qemu/target/arm/tcg/op_helper.c */

#include "jove.macros.h"

#define JOVE_SYS_ATTR _NOINL _UNUSED
#define JOVE_CRASH_MODE 'a'

#include "jove.util.c.inc"

#define JOVE_SYS_ATTR __attribute__((noinline))

#include "jove_sys.h"

static void do_syscall(CPUARMState *);
_NOINL _NORET static void not_syscall(uint32_t excp) {
  switch (excp) {
  default:
    __UNREACHABLE();

#define __CASE(excp)                                                           \
  case BOOST_PP_CAT(EXCP_,excp):                                               \
    _DUMP("EXCP_" BOOST_PP_STRINGIZE(excp) "\n");                              \
    break;

    __CASE(UDEF)
    __CASE(PREFETCH_ABORT)
    __CASE(DATA_ABORT)
    __CASE(IRQ)
    __CASE(FIQ)
    __CASE(BKPT)
    __CASE(EXCEPTION_EXIT)
    __CASE(KERNEL_TRAP)
    __CASE(HVC)
    __CASE(HYP_TRAP)
    __CASE(SMC)
    __CASE(VIRQ)
    __CASE(VFIQ)
    __CASE(SEMIHOST)
    __CASE(NOCP)
    __CASE(INVSTATE)
    __CASE(STKOF)
    __CASE(LAZYFP)
    __CASE(LSERR)
    __CASE(UNALIGNED)
    __CASE(DIVBYZERO)
    __CASE(VSERR)
    __CASE(GPC)
    __CASE(NMI)
    __CASE(VINMI)
    __CASE(VFNMI)
    __CASE(MON_TRAP)

#undef __CASE
  }

  _jove_sys_exit_group(0);
}

_INL _FLATTEN void handle(CPUARMState *env, uint32_t excp) {
  if (excp == EXCP_SWI)
    do_syscall(env);
  else
    not_syscall(excp);
}

void do_syscall(CPUARMState *env) {
  unsigned long sysnum = env->xregs[8];

#define env_a1 env->xregs[0]
#define env_a2 env->xregs[1]
#define env_a3 env->xregs[2]
#define env_a4 env->xregs[3]
#define env_a5 env->xregs[4]
#define env_a6 env->xregs[5]

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

  unsigned long sysret;
  switch (sysnum) {
  default: {
    char buff[65];
    _uint_to_string(sysnum, buff, 10);
    _strcat(buff, ")\n");

    _DUMP(buff);

    __builtin_trap();
    __builtin_unreachable();
  }

#define ___SYSCALL0(nr, nm)                                                    \
  case nr:                                                                     \
    sysret = _jove_sys_##nm();                                                 \
    break;

#define ___SYSCALL1(nr, nm, t1, a1)                                            \
  case nr:                                                                     \
    sysret = _jove_sys_##nm((t1)_a1);                                          \
    break;

#define ___SYSCALL2(nr, nm, t1, a1, t2, a2)                                    \
  case nr:                                                                     \
    sysret = _jove_sys_##nm((t1)_a1, (t2)_a2);                                 \
    break;

#define ___SYSCALL3(nr, nm, t1, a1, t2, a2, t3, a3)                            \
  case nr:                                                                     \
    sysret = _jove_sys_##nm((t1)_a1, (t2)_a2, (t3)_a3);                        \
    break;

#define ___SYSCALL4(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4)                    \
  case nr:                                                                     \
    sysret = _jove_sys_##nm((t1)_a1, (t2)_a2, (t3)_a3, (t4)_a4);               \
    break;

#define ___SYSCALL5(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)            \
  case nr:                                                                     \
    sysret = _jove_sys_##nm((t1)_a1, (t2)_a2, (t3)_a3, (t4)_a4, (t5)_a5);      \
    break;

#define ___SYSCALL6(nr, nm, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)    \
  case nr:                                                                     \
    sysret =                                                                   \
        _jove_sys_##nm((t1)_a1, (t2)_a2, (t3)_a3, (t4)_a4, (t5)_a5, (t6)_a6);  \
    break;

#include "syscalls.inc.h"
  }

  env->xregs[0] = sysret;
}

static void ____(void) { /* see qemu/target/arm/tcg/op_helper.c */
