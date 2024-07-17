#include "cpu_state.h"
#include <stddef.h>

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
#include "jove.common.h"

#define JOVE_SYS_ATTR _INL _UNUSED

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

static bool _jove_see_through_tramp(const void *ptr, uintptr_t *out);

#include "jove.llvm.c"
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
                 uint32_t init_sp /* formerly a3 */) {
  _jove_initialize();

  __jove_env.active_tc.gpr[4] = a0;
  __jove_env.active_tc.gpr[5] = a1;
  __jove_env.active_tc.gpr[2] = v0;
  __jove_env.active_tc.gpr[29] = _jove_begin_setup_emulated_stack(init_sp);

  return _jove_call_entry();
}

#define JOVE_THUNK_PROLOGUE                                                    \
  ".set noreorder\n"                                                           \
                                                                               \
  "addiu $sp,$sp,-32\n"                                                        \
  "sw $ra, 20($sp)\n" /* callee-saved registers */                             \
  "sw $s0, 24($sp)\n"                                                          \
  "sw $s1, 28($sp)\n"

#define JOVE_THUNK_EPILOGUE                                                    \
  "lw $ra, 20($sp)\n" /* callee-saved registers */                             \
  "lw $s0, 24($sp)\n"                                                          \
  "lw $s1, 28($sp)\n"                                                          \
                                                                               \
  "jr $ra\n"                                                                   \
  "addiu $sp,$sp,32\n"                                                         \
                                                                               \
  ".set reorder\n"

#define JOVE_THUNK_EXTRA_ARGS                                                  \
  "ldc1 $f12, 380($s1)\n" /* floating point arguments */                       \
  "ldc1 $f14, 412($s1)\n"

#define JOVE_THUNK_EXTRA_RETS                                                  \
  "sdc1 $f0, 188($s1)\n" /* floating point return values */                    \
  "sdc1 $f2, 220($s1)\n"                                                       \

#define JOVE_THUNK_CORE                                                        \
  JOVE_THUNK_EXTRA_ARGS                                                        \
                                                                               \
  "move $s0, $sp\n" /* save sp in $s0 */                                       \
                                                                               \
  "lw $sp, 0($s1)\n"   /* sp=*emuspp */                                        \
  "sw $zero, 0($s1)\n" /* *emuspp=NULL */                                      \
                                                                               \
  "jalr $t9\n" /* call dstpc */                                                \
  "nop\n"                                                                      \
                                                                               \
  "sw $sp, 0($s1)\n" /* store modified emusp */                                \
  "move $sp, $s0\n"  /* restore stack pointer */                               \
                                                                               \
  JOVE_THUNK_EXTRA_RETS                                                        \
                                                                               \
  JOVE_THUNK_EPILOGUE

//
// NOTE: the magic offset is
// offsetof(CPUMIPSState, active_fpu.fpr[0].d) -
// offsetof(CPUMIPSState, active_tc.gpr[29]);
//

jove_thunk_return_t _jove_thunk0(uint32_t dstpc   /* a0 */,
                                 uint32_t *emuspp /* a1 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $t9, $a0\n" // dstpc in t9
               "move $s1, $a1\n" // emuspp in s1

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk1(uint32_t a0,
                                 uint32_t dstpc   /* a1 */,
                                 uint32_t *emuspp /* a2 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $t9, $a1\n" // dstpc in t9
               "move $s1, $a2\n" // emuspp in s1

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk2(uint32_t a0,
                                 uint32_t a1,
                                 uint32_t dstpc   /* a2 */,
                                 uint32_t *emuspp /* a3 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $t9, $a2\n" // dstpc in t9
               "move $s1, $a3\n" // emuspp in s1

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk3(uint32_t a0,
                                 uint32_t a1,
                                 uint32_t a2,
                                 uint32_t dstpc /* a3 */,
                                 uint32_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $t9, $a3\n"   // dstpc in t9
               "lw $s1, 48($sp)\n" // emuspp in s1

               JOVE_THUNK_CORE
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

               "lw $t9, 48($sp)\n" // dstpc in t9
               "lw $s1, 52($sp)\n" // emuspp in s1

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

#undef JOVE_THUNK_PROLOGUE
#undef JOVE_THUNK_EPILOGUE

asm(".text\n"
    ".globl _jove_init"           "\n"
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

//
// XXX hack for glibc 2.32+
//
asm(".text\n"
    ".globl _jove__libc_early_init"                       "\n"
    "_jove__libc_early_init: .ent _jove__libc_early_init" "\n"
    ".set noreorder"                                      "\n"
    ".cpload $t9"                                         "\n"
    ".set reorder"                                        "\n"

    "subu $sp, $sp, 32" "\n" /* allocate stack memory */

    "sw $a0,8($sp)"  "\n" /* save args */
    "sw $a1,12($sp)" "\n"
    "sw $a2,16($sp)" "\n"
    "sw $a3,20($sp)" "\n"

    "sw $ra,24($sp)" "\n" /* save ra */
    "sw $gp,28($sp)" "\n" /* save gp */

    "la $t9, _jove_do_call_rt_init" "\n"
    "jalr $t9"                      "\n"

    "lw $gp,28($sp)" "\n" /* gp could have been clobbered */

    "la $t9, _jove_initialize" "\n"
    "jalr $t9"                 "\n"

    "lw $gp,28($sp)" "\n" /* gp could have been clobbered */

    "la $t9, _jove_get_libc_early_init_fn_sect_ptr" "\n"
    "jalr $t9"                                      "\n"

    "move $t9, $v0"  "\n"
    "jalr $t9"       "\n"

    "lw $gp,28($sp)" "\n" /* gp could have been clobbered */

    "lw $a0,8($sp)"  "\n" /* restore args */
    "lw $a1,12($sp)" "\n"
    "lw $a2,16($sp)" "\n"
    "lw $a3,20($sp)" "\n"

    "lw $ra,24($sp)"     "\n" /* restore ra */
    "addiu $sp, $sp, 32" "\n" /* deallocate stack memory */

    "jr $ra"                      "\n"
    ".end _jove__libc_early_init" "\n");

_HIDDEN void _jove_do_call_rt_init(void) {
  _jove_rt_init();
}

bool _jove_see_through_tramp(const void *ptr, uintptr_t *out) {
  return false;
}
