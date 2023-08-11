#include "cpu_state.h"
#include <stddef.h>

extern /* __thread */ CPUMIPSState __jove_env;
static /* __thread */ CPUMIPSState *__jove_env_clunk = &__jove_env;

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

_NAKED jove_thunk_return_t _jove_thunk5(uint64_t a0,
                                        uint64_t a1,
                                        uint64_t a2,
                                        uint64_t a3,
                                        uint64_t a4,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk6(uint64_t a0,
                                        uint64_t a1,
                                        uint64_t a2,
                                        uint64_t a3,
                                        uint64_t a4,
                                        uint64_t a5,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk7(uint64_t a0,
                                        uint64_t a1,
                                        uint64_t a2,
                                        uint64_t a3,
                                        uint64_t a4,
                                        uint64_t a5,
                                        uint64_t a6,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk8(uint64_t a0,
                                        uint64_t a1,
                                        uint64_t a2,
                                        uint64_t a3,
                                        uint64_t a4,
                                        uint64_t a5,
                                        uint64_t a6,
                                        uint64_t a7,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

#include "jove.llvm.c"
#include "jove.arch.c"
#include "jove.util.c"
#include "jove.common.c"
#include "jove.recover.c"

_HIDDEN void _jove_begin(uint64_t a0,
                         uint64_t a1,
                         uint64_t v0,     /* formerly a2 */
                         uint64_t sp_addr /* formerly a3 */);

#define __STRING(x)	#x
#define __CONCAT(x,y)	x ## y
#define STRINGXP(X) __STRING(X)
#define STRINGXV(X) STRINGV_(X)
#define STRINGV_(...) # __VA_ARGS__

# define _ASM_FN_PROLOGUE(entry)					\
	".globl\t" __STRING(entry) "\n\t"				\
	".ent\t" __STRING(entry) "\n\t"					\
	".type\t" __STRING(entry) ", @function\n"			\
	__STRING(entry) ":\n\t"

# define _ASM_FN_EPILOGUE(entry)					\
	".end\t" __STRING(entry) "\n\t"					\
	".size\t" __STRING(entry) ", . - " __STRING(entry) "\n\t"

# define SETUP_GPX64(cp_reg, ra_save)			\
		move ra_save, $31; /* Save old ra.  */	\
		.set noreorder;				\
		bal 10f; /* Find addr of .cpsetup.  */	\
		nop;					\
10:							\
		.set reorder;				\
		.cpsetup $31, cp_reg, 10b;		\
		move $31, ra_save

/* when we can rely on t9 being set */
# define SETUP_GP64(gpreg, proc) \
		move gpreg, $gp; \
		.cpsetup $25, gpreg, proc

asm(".text\n"
    _ASM_FN_PROLOGUE(_jove_start) "\n"

    STRINGXV(SETUP_GPX64($0,$0))  "\n"

    /* The return address register is set to zero so that programs
       that search backword through stack frames recognize the last
       stack frame. */
    "move $ra, $0"                "\n"

    "move $a2, $v0"               "\n"
    "move $a3, $sp"               "\n"

    "dla $t9, _jove_begin"        "\n"
    "jalr $t9"                    "\n"
    "nop"                         "\n"

    "break"                       "\n"

    _ASM_FN_EPILOGUE(_jove_start) "\n"
    ".previous");

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
  "daddiu $sp,$sp,-64\n"                                                       \
  "sd $ra, 8($sp)\n"                                                           \
  "sd $s0, 16($sp)\n"                                                          \
  "sd $s1, 24($sp)\n"                                                          \
                                                                               \
  "move $s0, $sp\n" /* save sp in $s0 */

#define JOVE_THUNK_EPILOGUE                                                    \
  "sd $sp, 0($s1)\n" /* store modified emusp */                                \
  "move $sp, $s0\n"  /* restore stack pointer */                               \
                                                                               \
  "ld $ra, 8($sp)\n"                                                           \
  "ld $s0, 16($sp)\n"                                                          \
  "ld $s1, 24($sp)\n"                                                          \
                                                                               \
  "jr $ra\n"                                                                   \
  "daddiu $sp,$sp,64\n"                                                        \
                                                                               \
  ".set reorder\n"

//
// NOTE: the magic offset is
// offsetof(CPUMIPSState, active_fpu.fpr[0].d) -
// offsetof(CPUMIPSState, active_tc.gpr[29]);
//

jove_thunk_return_t _jove_thunk0(uint64_t dstpc,  /* a0 */
                                 uint64_t *emuspp /* a1 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $s1, $a1\n" // emuspp in $s1

               "ld $sp, 0($a1)\n" // sp=*emuspp
               "sd $zero, 0($a1)\n" // *emuspp=NULL

               /* args: nothing to do */

               "jalr $a0\n"      // call dstpc
               "move $t9, $a0\n" // [delay slot] set t9

               JOVE_THUNK_EPILOGUE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk1(uint64_t a0,
                                 uint64_t dstpc,  /* a1 */
                                 uint64_t *emuspp /* a2 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $s1, $a2\n" // emuspp in $s1

               "ld $sp, 0($a2)\n" // sp=*emuspp
               "sd $zero, 0($a2)\n" // *emuspp=NULL

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
                                 uint64_t dstpc,  /* a2 */
                                 uint64_t *emuspp /* a3 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $s1, $a3\n" // emuspp in $s1

               "ld $sp, 0($a3)\n" // sp=*emuspp
               "sd $zero, 0($a3)\n" // *emuspp=NULL

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
                                 uint64_t dstpc,  /* a3 */
                                 uint64_t *emuspp /* $8 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $s1, $8\n" // emuspp in $s1

               "ld $sp, 0($s1)\n" // sp=*emuspp
               "sd $zero, 0($s1)\n" // *emuspp=NULL

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
                                 uint64_t dstpc,  /* $8 */
                                 uint64_t *emuspp /* $9 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $s1, $9\n" // emuspp in $s1

               /* args: nothing to do */

               "ld $sp, 0($s1)\n" // sp=*emuspp
               "sd $zero, 0($s1)\n" // *emuspp=NULL

               "jalr $8\n"      // call dstpc
               "move $t9, $8\n" // [delay slot] set t9

               JOVE_THUNK_EPILOGUE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk5(uint64_t a0,
                                 uint64_t a1,
                                 uint64_t a2,
                                 uint64_t a3,
                                 uint64_t a4,     /* $8 */
                                 uint64_t dstpc,  /* $9 */
                                 uint64_t *emuspp /* $10 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $s1, $10\n" // emuspp in $s1

               /* args: nothing to do */

               "ld $sp, 0($s1)\n" // sp=*emuspp
               "sd $zero, 0($s1)\n" // *emuspp=NULL

               "jalr $9\n"      // call dstpc
               "move $t9, $9\n" // [delay slot] set t9

               JOVE_THUNK_EPILOGUE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk6(uint64_t a0,
                                 uint64_t a1,
                                 uint64_t a2,
                                 uint64_t a3,
                                 uint64_t a4,     /* $8 */
                                 uint64_t a5,     /* $9 */
                                 uint64_t dstpc,  /* $10 */
                                 uint64_t *emuspp /* $11 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $s1, $11\n" // emuspp in $s1

               /* args: nothing to do */

               "ld $sp, 0($s1)\n" // sp=*emuspp
               "sd $zero, 0($s1)\n" // *emuspp=NULL

               "jalr $10\n"      // call dstpc
               "move $t9, $10\n" // [delay slot] set t9

               JOVE_THUNK_EPILOGUE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk7(uint64_t a0,
                                 uint64_t a1,
                                 uint64_t a2,
                                 uint64_t a3,
                                 uint64_t a4,     /* $8 */
                                 uint64_t a5,     /* $9 */
                                 uint64_t a6,     /* $10 */
                                 uint64_t dstpc,  /* $11 */
                                 uint64_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "ld $s1, 64($sp)\n" // emuspp in $s1

               /* args: nothing to do */

               "ld $sp, 0($s1)\n" // sp=*emuspp
               "sd $zero, 0($s1)\n" // *emuspp=NULL

               "jalr $11\n"      // call dstpc
               "move $t9, $11\n" // [delay slot] set t9

               JOVE_THUNK_EPILOGUE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk8(uint64_t a0,
                                 uint64_t a1,
                                 uint64_t a2,
                                 uint64_t a3,
                                 uint64_t a4, /* $8 */
                                 uint64_t a5, /* $9 */
                                 uint64_t a6, /* $10 */
                                 uint64_t a7, /* $11 */
                                 uint64_t dstpc,
                                 uint64_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "ld $t9, 64($sp)\n" // pc in $t9
               "ld $s1, 72($sp)\n" // emuspp in $s1

               /* args: nothing to do */

               "ld $sp, 0($s1)\n" // sp=*emuspp
               "sd $zero, 0($s1)\n" // *emuspp=NULL

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
    _ASM_FN_PROLOGUE(_jove_init)         "\n"
    STRINGXV(SETUP_GP64($24,_jove_init)) "\n"

    ".set noreorder\n"

    "daddiu $sp, $sp, -64" "\n" /* allocate stack memory */

    "sd $a0,8($sp)"  "\n" /* save args */
    "sd $a1,16($sp)" "\n"
    "sd $a2,24($sp)" "\n"
    "sd $a3,32($sp)" "\n"

    "sd $ra,40($sp)" "\n" /* save ra */
    "sd $gp,48($sp)" "\n" /* save our gp */
    "sd $24,56($sp)" "\n" /* save original gp */

    /* XXX MAGIC INSTRUCTION BYTES XXX */
    "li $zero, 2345"  "\n" /* nop */
    "li $zero, 345"   "\n" /* nop */
    "li $zero, 45"    "\n" /* nop */
    "li $zero, 5"     "\n" /* nop */
    "li $zero, 54"    "\n" /* nop */
    "li $zero, 543"   "\n" /* nop */
    "li $zero, 5432"  "\n" /* nop */

    "dla $t9, _jove_initialize" "\n"
    "jalr $t9"                  "\n"
    "nop"                       "\n"

    "ld $gp,48($sp)" "\n" /* our gp could have been clobbered */

    "dla $t9, _jove_get_init_fn_sect_ptr" "\n"
    "jalr $t9"                            "\n"
    "nop"                                 "\n"

    "beqz $v0, 10f" "\n" /* does DT_INIT function exist? */

    "ld $a0,8($sp)"  "\n" /* restore args */
    "ld $a1,16($sp)" "\n"
    "ld $a2,24($sp)" "\n"
    "ld $a3,32($sp)" "\n"

    "move $t9, $v0" "\n"
    "jalr $t9"      "\n" /* call DT_INIT function */
    "nop"           "\n"

"10: ld $ra,40($sp)"      "\n" /* restore ra */
    "ld $gp,56($sp)"      "\n" /* restore original gp */
    "daddiu $sp, $sp, 64" "\n" /* deallocate stack memory */

    "jr $ra" "\n"
    "nop"    "\n"

    ".set reorder\n"
    _ASM_FN_EPILOGUE(_jove_init) "\n"
    ".previous");

//
// XXX hack for glibc 2.32+
//
asm(".text\n"
    _ASM_FN_PROLOGUE(_jove__libc_early_init)         "\n"
    STRINGXV(SETUP_GP64($24,_jove__libc_early_init)) "\n"

    ".set noreorder\n"

    "daddiu $sp, $sp, -64" "\n" /* allocate stack memory */

    "sd $a0,8($sp)"  "\n" /* save args */
    "sd $a1,16($sp)" "\n"
    "sd $a2,24($sp)" "\n"
    "sd $a3,32($sp)" "\n"

    "sd $ra,40($sp)" "\n" /* save ra */
    "sd $gp,48($sp)" "\n" /* save ouur gp */
    "sd $24,56($sp)" "\n" /* save original gp */

    "dla $t9, _jove_do_call_rt_init" "\n"
    "jalr $t9"                       "\n"
    "nop"                            "\n"

    "ld $gp,48($sp)" "\n" /* our gp could have been clobbered */

    "dla $t9, _jove_initialize" "\n"
    "jalr $t9"                  "\n"
    "nop"                       "\n"

    "ld $gp,48($sp)" "\n" /* our gp could have been clobbered */

    "dla $t9, _jove_get_libc_early_init_fn_sect_ptr" "\n"
    "jalr $t9"                                       "\n"
    "nop"                                            "\n"

    "ld $a0,8($sp)"  "\n" /* restore args */
    "ld $a1,16($sp)" "\n"
    "ld $a2,24($sp)" "\n"
    "ld $a3,32($sp)" "\n"

    "move $t9, $v0" "\n"
    "jalr $t9"      "\n" /* call the (recompiled) __libc_early_init */
    "nop"           "\n"

    "ld $ra,40($sp)"      "\n" /* restore ra */
    "ld $gp,56($sp)"      "\n" /* restore original gp */
    "daddiu $sp, $sp, 64" "\n" /* deallocate stack memory */

    "jr $ra" "\n"
    "nop"    "\n"

    ".set reorder\n"
    _ASM_FN_EPILOGUE(_jove__libc_early_init) "\n"
    ".previous");

_HIDDEN void _jove_do_call_rt_init(void) {
  _jove_rt_init();
}
