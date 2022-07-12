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

_NAKED jove_thunk_return_t _jove_thunk0(uint32_t dstpc,
                                        uint32_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk1(uint32_t a0,
                                        uint32_t dstpc,
                                        uint32_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk2(uint32_t a0,
                                        uint32_t a1,
                                        uint32_t dstpc,
                                        uint32_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk3(uint32_t a0,
                                        uint32_t a1,
                                        uint32_t a2,
                                        uint32_t dstpc,
                                        uint32_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk4(uint32_t a0,
                                        uint32_t a1,
                                        uint32_t a2,
                                        uint32_t a3,
                                        uint32_t dstpc,
                                        uint32_t *emuspp);

_HIDDEN uintptr_t _jove_get_init_fn_sect_ptr(void);

#include "jove.llvm.c"
#include "jove.arch.c"
#include "jove.util.c"
#include "jove.common.c"
#include "jove.recover.c"

_HIDDEN
_NAKED void _jove_start(void);
_HIDDEN void _jove_begin(uint32_t a0,
                         uint32_t a1,
                         uint32_t v0,     /* formerly a2 */
                         uint32_t sp_addr /* formerly a3 */);

void _jove_start(void) {
  asm volatile(".set noreorder"      "\n"
               ".cpload $t9"         "\n" /* set up gp */

               /* The return address register is set to zero so that programs
                  that search backword through stack frames recognize the last
                  stack frame. */
               "move $ra, $0"        "\n"

               "move $a2, $v0"       "\n"
               "move $a3, $sp"       "\n"

               "la $t9, _jove_begin" "\n" /* needs gp set up */
               "jalr $t9"            "\n"
               "nop"                 "\n"

               "break"               "\n"
               ".set reorder"        "\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

void _jove_begin(uint32_t a0,
                 uint32_t a1,
                 uint32_t v0,     /* formerly a2 */
                 uint32_t sp_addr /* formerly a3 */) {
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

  //
  // we call _jove_rt_init here in case the dynamic linker transfers control
  // to the entry function before calling the ctors of libjove_rt (ae: i have
  // witnessed this happnening)
  //
  if (_jove_rt_init_clunk)
    _jove_rt_init_clunk();

  _jove_initialize();

  return _jove_call_entry();
}

#define JOVE_THUNK_PROLOGUE                                                    \
  ".set noreorder\n"                                                           \
                                                                               \
  "addiu $sp,$sp,-32\n"                                                        \
  "sw $ra, 20($sp)\n"                                                          \
  "sw $s0, 24($sp)\n"                                                          \
  "sw $s1, 28($sp)\n"                                                          \
                                                                               \
  "move $s0, $sp\n" /* save sp in $s0 */

#define JOVE_THUNK_EPILOGUE                                                    \
  "sdc1 $f0, 436($s1)\n" /* see NOTE below on magic offset */                  \
                                                                               \
  "sw $sp, 0($s1)\n" /* store modified emusp */                                \
  "move $sp, $s0\n"  /* restore stack pointer */                               \
                                                                               \
  "lw $ra, 20($sp)\n"                                                          \
  "lw $s0, 24($sp)\n"                                                          \
  "lw $s1, 28($sp)\n"                                                          \
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

jove_thunk_return_t _jove_thunk0(uint32_t dstpc,
                                 uint32_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $s1, $a1\n" // emuspp in $s1

               "ldc1 $f12, 628($a1)\n" // floating point argument #1
               "ldc1 $f14, 660($a1)\n" // floating point argument #2

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

jove_thunk_return_t _jove_thunk1(uint32_t a0,
                                 uint32_t dstpc,
                                 uint32_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $s1, $a2\n" // emuspp in $s1

               "ldc1 $f12, 628($a2)\n" // floating point argument #1
               "ldc1 $f14, 660($a2)\n" // floating point argument #2

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

jove_thunk_return_t _jove_thunk2(uint32_t a0,
                                 uint32_t a1,
                                 uint32_t dstpc,
                                 uint32_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $s1, $a3\n" // emuspp in $s1

               "ldc1 $f12, 628($a3)\n" // floating point argument #1
               "ldc1 $f14, 660($a3)\n" // floating point argument #2

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

jove_thunk_return_t _jove_thunk3(uint32_t a0,
                                 uint32_t a1,
                                 uint32_t a2,
                                 uint32_t dstpc,
                                 uint32_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "lw $s1, 48($sp)\n" // emuspp in $s1

               "ldc1 $f12, 628($s1)\n" // floating point argument #1
               "ldc1 $f14, 660($s1)\n" // floating point argument #2

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

jove_thunk_return_t _jove_thunk4(uint32_t a0,
                                 uint32_t a1,
                                 uint32_t a2,
                                 uint32_t a3,
                                 uint32_t dstpc,
                                 uint32_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "lw $s1, 52($sp)\n" // emuspp in $s1

               "ldc1 $f12, 628($s1)\n" // floating point argument #1
               "ldc1 $f14, 660($s1)\n" // floating point argument #2

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

asm(".text\n"
    "_jove_init: .ent _jove_init" "\n"
    ".set noreorder"              "\n"
    ".cpload $t9"                 "\n"
    ".set reorder"                "\n"

    "subu $sp, $sp, 32" "\n" /* allocate stack memory */

    "sw $a0,8($sp)"  "\n" /* save args */
    "sw $a1,12($sp)" "\n"
    "sw $a2,16($sp)" "\n"
    "sw $a3,20($sp)" "\n"

    "sw $ra,24($sp)" "\n" /* save ra */
    "sw $gp,28($sp)" "\n" /* save gp */

    /* XXX MAGIC INSTRUCTION BYTES XXX */
    "li $zero, 2345"  "\n" /* nop */
    "li $zero, 345"   "\n" /* nop */
    "li $zero, 45"    "\n" /* nop */
    "li $zero, 5"     "\n" /* nop */
    "li $zero, 54"    "\n" /* nop */
    "li $zero, 543"   "\n" /* nop */
    "li $zero, 5432"  "\n" /* nop */

    "la $t9, _jove_initialize" "\n"
    "jalr $t9"                 "\n"

    "lw $gp,28($sp)" "\n" /* gp could have been clobbered */

    "la $t9, _jove_get_init_fn_sect_ptr" "\n"
    "jalr $t9"                           "\n"

    "beqz $v0, 10f" "\n" /* does DT_INIT function exist? */

    "lw $a0,8($sp)"  "\n" /* restore args */
    "lw $a1,12($sp)" "\n"
    "lw $a2,16($sp)" "\n"
    "lw $a3,20($sp)" "\n"

    "move $t9, $v0" "\n"
    "jalr $t9"      "\n" /* call DT_INIT function */

"10: lw $ra,24($sp)"     "\n" /* restore ra */
    "addiu $sp, $sp, 32" "\n" /* deallocate stack memory */

    "jr $ra"          "\n"
    ".end _jove_init" "\n");
