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
#include <stdbool.h>

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

typedef unsigned __int128 jove_thunk_return_t;

_NAKED jove_thunk_return_t _jove_thunk0(uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk1(uint64_t x0,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk2(uint64_t x0,
                                        uint64_t x1,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk3(uint64_t x0,
                                        uint64_t x1,
                                        uint64_t x2,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk4(uint64_t x0,
                                        uint64_t x1,
                                        uint64_t x2,
                                        uint64_t x3,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk5(uint64_t x0,
                                        uint64_t x1,
                                        uint64_t x2,
                                        uint64_t x3,
                                        uint64_t x4,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk6(uint64_t x0,
                                        uint64_t x1,
                                        uint64_t x2,
                                        uint64_t x3,
                                        uint64_t x4,
                                        uint64_t x5,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk7(uint64_t x0,
                                        uint64_t x1,
                                        uint64_t x2,
                                        uint64_t x3,
                                        uint64_t x4,
                                        uint64_t x5,
                                        uint64_t x6,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk8(uint64_t x0,
                                        uint64_t x1,
                                        uint64_t x2,
                                        uint64_t x3,
                                        uint64_t x4,
                                        uint64_t x5,
                                        uint64_t x6,
                                        uint64_t x7,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_HIDDEN uintptr_t _jove_alloc_stack(void);
_HIDDEN void _jove_free_stack(uintptr_t);

#include "jove.llvm.c"
#include "jove.arch.c"
#include "jove.util.c"
#include "jove.common.c"
#include "jove.recover.c"

_HIDDEN
_NAKED void _jove_start(void);
_HIDDEN void _jove_begin(uint64_t x0,
                         uint64_t x1,
                         uint64_t x2,
                         uint64_t x3,
                         uint64_t x4,
                         uint64_t x5,
                         uint64_t x6,
                         uint64_t sp_addr /* formerly x7 */);

void _jove_start(void) {
  asm volatile(/* Create an initial frame with 0 LR and FP */
               "mov x29, #0\n"
               "mov x30, #0\n"

               "mov x7, sp\n"
               "b _jove_begin\n");
}

void _jove_begin(uint64_t x0,
                 uint64_t x1,
                 uint64_t x2,
                 uint64_t x3,
                 uint64_t x4,
                 uint64_t x5,
                 uint64_t x6,
                 uint64_t sp_addr /* formerly x7 */) {
  __jove_env_clunk->xregs[0] = x0;
  __jove_env_clunk->xregs[1] = x1;
  __jove_env_clunk->xregs[2] = x2;
  __jove_env_clunk->xregs[3] = x3;
  __jove_env_clunk->xregs[4] = x4;
  __jove_env_clunk->xregs[5] = x5;
  __jove_env_clunk->xregs[6] = x6;

  //
  // setup the stack
  //
  {
    unsigned len = _get_stack_end() - sp_addr;

    unsigned long env_stack_beg = _jove_alloc_stack();
    unsigned long env_stack_end = env_stack_beg + JOVE_STACK_SIZE;

    char *env_sp = (char *)(env_stack_end - JOVE_PAGE_SIZE - len);

    _memcpy(env_sp, (void *)sp_addr, len);

    __jove_env_clunk->xregs[31] = (target_ulong)env_sp;
  }

  _jove_initialize();

  return _jove_call_entry();
}

#define JOVE_THUNK_PROLOGUE                                                    \
  "stp x29, x30, [sp, #-128]!\n" /* push frame */                              \
                                                                               \
/*"stp x19, x20, [sp, #16]\n"*//* callee-saved registers */                    \
  "stp x21, x22, [sp, #32]\n"                                                  \
/*"stp x23, x24, [sp, #48]\n"*/                                                \
/*"stp x25, x26, [sp, #64]\n"*/                                                \
/*"stp x27, x28, [sp, #80]\n"*/                                                \

#define JOVE_THUNK_EPILOGUE                                                    \
                                                                               \
/*"ldp x19, x20, [sp, #16]\n"*//* callee-saved registers */                    \
  "ldp x21, x22, [sp, #32]\n"                                                  \
/*"ldp x23, x24, [sp, #48]\n"*/                                                \
/*"ldp x25, x26, [sp, #64]\n"*/                                                \
/*"ldp x27, x28, [sp, #80]\n"*/                                                \
                                                                               \
  "ldp x29, x30, [sp], #128\n" /* restore frame */                             \
                                                                               \
  "ret\n"

#define JOVE_THUNK_EXTRA_ARGS                                                  \
  "ldr d0, [x21, #2920]\n"                                                     \
  "ldr d1, [x21, #3176]\n"                                                     \
  "ldr d2, [x21, #3432]\n"                                                     \
  "ldr d3, [x21, #3688]\n"                                                     \
  "ldr d4, [x21, #3944]\n"                                                     \
  "ldr d5, [x21, #4200]\n"                                                     \
  "ldr d6, [x21, #4456]\n"                                                     \
  "ldr d7, [x21, #4712]\n"

#define JOVE_THUNK_EXTRA_RETS                                                  \
  "str d0, [x21, #2920]\n"                                                     \
  "str d1, [x21, #3176]\n"                                                     \
  "str d2, [x21, #3432]\n"                                                     \
  "str d3, [x21, #3688]\n"                                                     \
  "str d4, [x21, #3944]\n"                                                     \
  "str d5, [x21, #4200]\n"                                                     \
  "str d6, [x21, #4456]\n"                                                     \
  "str d7, [x21, #4712]\n"

#define JOVE_THUNK_CORE                                                        \
  JOVE_THUNK_EXTRA_ARGS                                                        \
                                                                               \
  "mov x22, sp\n" /* save sp in x22 */                                         \
                                                                               \
  "ldr x9, [x21]\n" /* sp=*emuspp */                                           \
  "mov sp, x9\n"                                                               \
  "str xzr, [x21]\n" /* *emuspp=NULL */                                        \
                                                                               \
  /* args: nothing to do */                                                    \
                                                                               \
  "blr x10\n" /* call dstpc */                                                 \
                                                                               \
  "mov x9, sp\n" /* store modified emusp */                                    \
  "str x9, [x21]\n"                                                            \
                                                                               \
  "mov sp, x22\n" /* restore stack pointer */                                  \
                                                                               \
  JOVE_THUNK_EXTRA_RETS                                                        \
                                                                               \
  JOVE_THUNK_EPILOGUE

jove_thunk_return_t _jove_thunk0(uint64_t dstpc   /* x0 */,
                                 uint64_t *emuspp /* x1 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x0\n" /* dstpc in x10 */
               "mov x21, x1\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk1(uint64_t x0,
                                 uint64_t dstpc   /* x1 */,
                                 uint64_t *emuspp /* x2 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x1\n" /* dstpc in x10 */
               "mov x21, x2\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk2(uint64_t x0,
                                 uint64_t x1,
                                 uint64_t dstpc   /* x2 */,
                                 uint64_t *emuspp /* x3 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x2\n" /* dstpc in x10 */
               "mov x21, x3\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk3(uint64_t x0,
                                 uint64_t x1,
                                 uint64_t x2,
                                 uint64_t dstpc   /* x3 */,
                                 uint64_t *emuspp /* x4 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x3\n" /* dstpc in x10 */
               "mov x21, x4\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk4(uint64_t x0,
                                 uint64_t x1,
                                 uint64_t x2,
                                 uint64_t x3,
                                 uint64_t dstpc   /* x4 */,
                                 uint64_t *emuspp /* x5 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x4\n" /* dstpc in x10 */
               "mov x21, x5\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk5(uint64_t x0,
                                 uint64_t x1,
                                 uint64_t x2,
                                 uint64_t x3,
                                 uint64_t x4,
                                 uint64_t dstpc   /* x5 */,
                                 uint64_t *emuspp /* x6 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x5\n" /* dstpc in x10 */
               "mov x21, x6\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk6(uint64_t x0,
                                 uint64_t x1,
                                 uint64_t x2,
                                 uint64_t x3,
                                 uint64_t x4,
                                 uint64_t x5,
                                 uint64_t dstpc   /* x6 */,
                                 uint64_t *emuspp /* x7 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x6\n" /* dstpc in x10 */
               "mov x21, x7\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk7(uint64_t x0,
                                 uint64_t x1,
                                 uint64_t x2,
                                 uint64_t x3,
                                 uint64_t x4,
                                 uint64_t x5,
                                 uint64_t x6,
                                 uint64_t dstpc   /* x7 */,
                                 uint64_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x7\n"         /* dstpc in x10 */
               "ldr x21, [sp, #128]\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk8(uint64_t x0,
                                 uint64_t x1,
                                 uint64_t x2,
                                 uint64_t x3,
                                 uint64_t x4,
                                 uint64_t x5,
                                 uint64_t x6,
                                 uint64_t x7,
                                 uint64_t dstpc,
                                 uint64_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "ldr x10, [sp, #128]\n" /* dstpc in x10 */
               "ldr x21, [sp, #136]\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

#undef JOVE_THUNK_PROLOGUE
#undef JOVE_THUNK_EPILOGUE
