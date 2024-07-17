#include "cpu_state.h"

#include "jove.common.h"

typedef unsigned __int128 jove_thunk_return_t;

#include "jove.common.c"

_HIDDEN
_NAKED void _jove_start(void);
_HIDDEN void _jove_begin(uintptr_t x0,
                         uintptr_t x1,
                         uintptr_t x2,
                         uintptr_t x3,
                         uintptr_t x4,
                         uintptr_t x5,
                         uintptr_t x6,
                         uintptr_t sp_addr /* formerly x7 */);

void _jove_start(void) {
  asm volatile(/* Create an initial frame with 0 LR and FP */
               "mov x29, #0\n"
               "mov x30, #0\n"

               "mov x7, sp\n"
               "b _jove_begin\n");
}

void _jove_begin(uintptr_t x0,
                 uintptr_t x1,
                 uintptr_t x2,
                 uintptr_t x3,
                 uintptr_t x4,
                 uintptr_t x5,
                 uintptr_t x6,
                 uintptr_t init_sp /* formerly x7 */) {
  _jove_initialize();

  __jove_env.xregs[0] = x0;
  __jove_env.xregs[1] = x1;
  __jove_env.xregs[2] = x2;
  __jove_env.xregs[3] = x3;
  __jove_env.xregs[4] = x4;
  __jove_env.xregs[5] = x5;
  __jove_env.xregs[6] = x6;
  __jove_env.xregs[31] = _jove_begin_setup_emulated_stack(init_sp);

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

jove_thunk_return_t _jove_thunk0(uintptr_t dstpc   /* x0 */,
                                 uintptr_t *emuspp /* x1 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x0\n" /* dstpc in x10 */
               "mov x21, x1\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk1(uintptr_t x0,
                                 uintptr_t dstpc   /* x1 */,
                                 uintptr_t *emuspp /* x2 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x1\n" /* dstpc in x10 */
               "mov x21, x2\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk2(uintptr_t x0,
                                 uintptr_t x1,
                                 uintptr_t dstpc   /* x2 */,
                                 uintptr_t *emuspp /* x3 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x2\n" /* dstpc in x10 */
               "mov x21, x3\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk3(uintptr_t x0,
                                 uintptr_t x1,
                                 uintptr_t x2,
                                 uintptr_t dstpc   /* x3 */,
                                 uintptr_t *emuspp /* x4 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x3\n" /* dstpc in x10 */
               "mov x21, x4\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk4(uintptr_t x0,
                                 uintptr_t x1,
                                 uintptr_t x2,
                                 uintptr_t x3,
                                 uintptr_t dstpc   /* x4 */,
                                 uintptr_t *emuspp /* x5 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x4\n" /* dstpc in x10 */
               "mov x21, x5\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk5(uintptr_t x0,
                                 uintptr_t x1,
                                 uintptr_t x2,
                                 uintptr_t x3,
                                 uintptr_t x4,
                                 uintptr_t dstpc   /* x5 */,
                                 uintptr_t *emuspp /* x6 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x5\n" /* dstpc in x10 */
               "mov x21, x6\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk6(uintptr_t x0,
                                 uintptr_t x1,
                                 uintptr_t x2,
                                 uintptr_t x3,
                                 uintptr_t x4,
                                 uintptr_t x5,
                                 uintptr_t dstpc   /* x6 */,
                                 uintptr_t *emuspp /* x7 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x6\n" /* dstpc in x10 */
               "mov x21, x7\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk7(uintptr_t x0,
                                 uintptr_t x1,
                                 uintptr_t x2,
                                 uintptr_t x3,
                                 uintptr_t x4,
                                 uintptr_t x5,
                                 uintptr_t x6,
                                 uintptr_t dstpc   /* x7 */,
                                 uintptr_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "mov x10, x7\n"         /* dstpc in x10 */
               "ldr x21, [sp, #128]\n" /* emuspp in x21 */

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk8(uintptr_t x0,
                                 uintptr_t x1,
                                 uintptr_t x2,
                                 uintptr_t x3,
                                 uintptr_t x4,
                                 uintptr_t x5,
                                 uintptr_t x6,
                                 uintptr_t x7,
                                 uintptr_t dstpc,
                                 uintptr_t *emuspp) {
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

bool _jove_see_through_tramp(const void *ptr, uintptr_t *out) {
  return false;
}
