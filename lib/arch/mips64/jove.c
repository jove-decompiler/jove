#include "cpu_state.h"
#include <stddef.h>

extern /* __thread */ struct CPUMIPSState __jove_env;
static /* __thread */ struct CPUMIPSState *__jove_env_clunk = &__jove_env;

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <signal.h>

#include <jove/jove.h> /* for TARGET_NUM_REG_ARGS */
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/punctuation/comma_if.hpp>
#include <boost/preprocessor/arithmetic/inc.hpp>
#include <boost/preprocessor/cat.hpp>

#include "jove.constants.h"
#include "jove.macros.h"
#include "jove.types.h"

#define JOVE_SYS_ATTR _INL _UNUSED
#include "jove_sys.h"

typedef uint64_t jove_thunk_return_t;

_NAKED jove_thunk_return_t _jove_thunk0(uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk1(uint64_t a0,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk2(uint64_t a0,
                                        uint64_t a1,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk3(uint64_t a0,
                                        uint64_t a1,
                                        uint64_t a2,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk4(uint64_t a0,
                                        uint64_t a1,
                                        uint64_t a2,
                                        uint64_t a3,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

#include "jove.llvm.c"
#include "jove.arch.c"
#include "jove.util.c"
#include "jove.common.c"
#include "jove.recover.c"

_HIDDEN
_NAKED void _jove_start(void);
static void _jove_begin(uint64_t a0,
                        uint64_t a1,
                        uint64_t v0,     /* formerly a2 */
                        uint64_t sp_addr /* formerly a3 */);

void _jove_start(void) {
  asm volatile(/* The return address register is set to zero so that programs that search backword through stack frames recognize the last stack frame. */
               "move $31, $0\n"

               "move $6, $2\n"  /* a2=v0 */
               "move $7, $29\n" /* a3=sp */

               "jalr %P0\n"
               "hlt: b hlt\n" /* Crash if somehow it does return. */

               : /* OutputOperands */
               : /* InputOperands */
               "i"(_jove_begin)
               : /* Clobbers */);
}

void _jove_begin(uint64_t a0,
                 uint64_t a1,
                 uint64_t v0,     /* formerly a2 */
                 uint64_t sp_addr /* formerly a3 */) {
  __jove_env_clunk->active_tc.gpr[4] = a0;
  __jove_env_clunk->active_tc.gpr[5] = a1;
  __jove_env_clunk->active_tc.gpr[2] = v0;

  //
  // setup the stack
  //
  {
    unsigned len = _get_stack_end() - sp_addr;

    unsigned long env_stack_beg = _jove_alloc_stack();
    unsigned long env_stack_end = env_stack_beg + JOVE_STACK_SIZE;

    char *env_sp = (char *)(env_stack_end - JOVE_PAGE_SIZE - len);

    _memcpy(env_sp, (void *)sp_addr, len);

    __jove_env_clunk->active_tc.gpr[29] = (target_ulong)env_sp;
  }

  _jove_initialize();

  return _jove_call_entry();
}

#define JOVE_THUNK_PROLOGUE                                                    \
  ".set noreorder\n"                                                           \
                                                                               \
  "addiu $sp,$sp,-32\n"                                                        \
  "sw $ra, 8($sp)\n"                                                           \
  "sw $s0, 16($sp)\n"                                                          \
  "sw $s1, 24($sp)\n"                                                          \
                                                                               \
  "move $s0, $sp\n" /* save sp in $s0 */

#define JOVE_THUNK_EPILOGUE                                                    \
  "sw $sp, 0($s1)\n" /* store modified emusp */                                \
  "move $sp, $s0\n"  /* restore stack pointer */                               \
                                                                               \
  "lw $ra, 8($sp)\n"                                                           \
  "lw $s0, 16($sp)\n"                                                          \
  "lw $s1, 24($sp)\n"                                                          \
                                                                               \
  "jr $ra\n"                                                                   \
  "addiu $sp,$sp,32\n"                                                         \
                                                                               \
  ".set reorder\n"

//
// NOTE: the magic offset is
// offsetof(CPUMIPSState, active_fpu.fpr[0].d) -
// offsetof(CPUMIPSState, active_tc.gpr[29]);
//

jove_thunk_return_t _jove_thunk0(uint64_t dstpc,
                                 uint64_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $s1, $a1\n" // emuspp in $s1

               "lw $sp, 0($a1)\n" // sp=*emuspp
               "sw $zero, 0($a1)\n" // *emuspp=NULL

               /* args: nothing to do */

               "jalr $a0\n"      // call dstpc
               "move $t9, $a0\n" // [delay slot] set t9

               JOVE_THUNK_EPILOGUE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk1(uint64_t a0,
                                 uint64_t dstpc,
                                 uint64_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $s1, $a2\n" // emuspp in $s1

               "lw $sp, 0($a2)\n" // sp=*emuspp
               "sw $zero, 0($a2)\n" // *emuspp=NULL

               /* args: nothing to do */

               "jalr $a1\n"      // call dstpc
               "move $t9, $a1\n" // [delay slot] set t9

               JOVE_THUNK_EPILOGUE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk2(uint64_t a0,
                                 uint64_t a1,
                                 uint64_t dstpc,
                                 uint64_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $s1, $a3\n" // emuspp in $s1

               "lw $sp, 0($a3)\n" // sp=*emuspp
               "sw $zero, 0($a3)\n" // *emuspp=NULL

               /* args: nothing to do */

               "jalr $a2\n"      // call dstpc
               "move $t9, $a2\n" // [delay slot] set t9

               JOVE_THUNK_EPILOGUE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk3(uint64_t a0,
                                 uint64_t a1,
                                 uint64_t a2,
                                 uint64_t dstpc,
                                 uint64_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "lw $s1, 48($sp)\n" // emuspp in $s1

               "lw $sp, 0($s1)\n" // sp=*emuspp
               "sw $zero, 0($s1)\n" // *emuspp=NULL

               /* args: nothing to do */

               "jalr $a3\n"      // call dstpc
               "move $t9, $a3\n" // [delay slot] set t9

               JOVE_THUNK_EPILOGUE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk4(uint64_t a0,
                                 uint64_t a1,
                                 uint64_t a2,
                                 uint64_t a3,
                                 uint64_t dstpc,
                                 uint64_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "lw $s1, 52($sp)\n" // emuspp in $s1

               /* args: nothing to do */

               "lw $t9, 48($sp)\n" /* do this now before sp is clobbered */

               "lw $sp, 0($s1)\n" // sp=*emuspp
               "sw $zero, 0($s1)\n" // *emuspp=NULL

               "jalr $t9\n"      // call dstpc
               "nop\n"

               JOVE_THUNK_EPILOGUE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

#undef JOVE_THUNK_PROLOGUE
#undef JOVE_THUNK_EPILOGUE
