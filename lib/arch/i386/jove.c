#include "cpu_state.h"

#include "jove.common.h"

#define JOVE_THUNK_ATTR _REGPARM
typedef uint64_t jove_thunk_return_t;

#include "jove.common.c"

_HIDDEN
_NAKED
void _jove_start(void) {
  asm volatile(/* Clear the frame pointer.  The ABI suggests this be done, to
                  mark the outermost frame obviously.  */
               "xorl %%ebp, %%ebp\n"

               /* save original sp */
               "movl %%esp, %%ecx\n"

               /* Align the stack to a 16 byte boundary to follow the ABI. */
               "andl $0xfffffff0, %%esp\n"

               /* pass original sp */
               "pushl %%ecx\n"
               "call _jove_begin\n"
               "hlt\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

_HIDDEN
void _jove_begin(uintptr_t init_sp) {
  _jove_initialize();

  __jove_env.regs[R_ESP] = _jove_begin_setup_emulated_stack(init_sp);

  _jove_call_entry();
}

extern floatx80 float32_to_floatx80(float32, float_status *status);

#define ST0    (env->fpregs[env->fpstt].d)

_HIDDEN void _jove_thunk_handle_st0(uintptr_t f32) {
  CPUX86State *env = &__jove_env;

#if 0
  helper_flds_ST0(env, f32);
#else
  env->fpstt = env->fpstt & 7;
  env->fp_status.float_exception_flags = 0;
  ST0 = float32_to_floatx80(f32, &env->fp_status);
#endif
}

#define JOVE_THUNK_PROLOGUE                                                    \
  "pushl %%ebp\n" /* callee-saved registers */                                 \
  "pushl %%edi\n"                                                              \
  "pushl %%esi\n"

#define JOVE_THUNK_EPILOGUE                                                    \
  "popl %%esi\n" /* callee-saved registers */                                  \
  "popl %%edi\n"                                                               \
  "popl %%ebp\n"                                                               \
  "ret\n"

#define JOVE_THUNK_EXTRA_RETS                                                  \
  "pushl %%eax\n" /* preserve */                                               \
  "pushl %%edx\n" /* preserve */                                               \
                                                                               \
  "pushl %%eax\n"                                                              \
  "fsts (%%esp)\n" /* get ST(0) as float */                                    \
  "call _jove_thunk_handle_st0\n"                                              \
  "popl %%eax\n"                                                               \
                                                                               \
  "popl %%edx\n"                                                               \
  "popl %%eax\n"

#define JOVE_THUNK_CORE                                                        \
  "movl %%esp, %%ebp\n" /* save sp in ebp */                                   \
                                                                               \
  "movl (%%edi), %%esp\n" /* sp=*emusp */                                      \
  "movl $0, (%%edi)\n"    /* *emusp=0x0 */                                     \
                                                                               \
  /* args: nothing to do */                                                    \
                                                                               \
  "addl $4, %%esp\n" /* replace return address on the stack */                 \
  "call *%%esi\n"    /* call dstpc */                                          \
                                                                               \
  "movl %%esp, (%%edi)\n" /* store modified emusp */                           \
  "movl %%ebp, %%esp\n"   /* restore stack pointer */                          \
                                                                               \
  JOVE_THUNK_EXTRA_RETS                                                        \
                                                                               \
  JOVE_THUNK_EPILOGUE

jove_thunk_return_t _jove_thunk0(uintptr_t dstpc,  /* eax */
                                 uintptr_t *emuspp /* edx */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movl %%eax, %%esi\n" /* dstpc in esi */
               "movl %%edx, %%edi\n" /* emuspp in edi */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk1(uintptr_t eax,
                                 uintptr_t dstpc,  /* edx */
                                 uintptr_t *emuspp /* ecx */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movl %%edx, %%esi\n" /* dstpc in esi */
               "movl %%ecx, %%edi\n" /* emuspp in edi */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk2(uintptr_t eax,
                                 uintptr_t edx,
                                 uintptr_t dstpc,  /* ecx */
                                 uintptr_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movl %%ecx, %%esi\n" /* dstpc in esi */
               "movl 16(%%esp), %%edi\n" /* emuspp in edi */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk3(uintptr_t eax,
                                 uintptr_t edx,
                                 uintptr_t ecx,
                                 uintptr_t dstpc,
                                 uintptr_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movl 16(%%esp), %%esi\n" /* dstpc in esi */
               "movl 20(%%esp), %%edi\n" /* emuspp in edi */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

_REGPARM
_NAKED
_HIDDEN
void _jove_init(uintptr_t eax,
                uintptr_t edx,
                uintptr_t ecx /* TODO preserve */) {
  asm volatile(
               "xchgl %%ebx, %%ebx\n" /* nop */
               "xchgl %%ecx, %%ecx\n" /* nop */
               "xchgl %%edx, %%edx\n" /* nop */
               "xchgl %%esi, %%esi\n" /* nop */
               "xchgl %%edi, %%edi\n" /* nop */

               "pushl %%eax\n" /* preserve arguments */
               "pushl %%edx\n"

               "call _jove_initialize\n"
               "call _jove_do_get_init_fn_sect_ptr\n"
               "movl %%eax, %%ecx\n"

               "popl %%edx\n"
               "popl %%eax\n"

               "test %%ecx, %%ecx\n" /* only call initfn if not-null */
               "je dont_call_initfn\n"

               "jmp *%%ecx\n"

               "dont_call_initfn:\n"
               "ret\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

//
// XXX hack for glibc 2.32+
//
_REGPARM
_NAKED
_HIDDEN
void _jove__libc_early_init(uintptr_t eax,
                            uintptr_t edx,
                            uintptr_t ecx /* TODO preserve */) {
  asm volatile("pushl %%eax\n" /* preserve arguments */
               "pushl %%edx\n"

               "call _jove_do_call_rt_init\n"
               "call _jove_initialize\n"
               "call _jove_get_libc_early_init_fn_sect_ptr\n"
               "movl %%eax, %%ecx\n"

               "popl %%edx\n" /* preserve arguments */
               "popl %%eax\n"

               "jmp *%%ecx\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

extern void _jove_rt_init(void);

_HIDDEN void _jove_do_call_rt_init(void) {
  _jove_rt_init();
}

_HIDDEN uintptr_t _jove_do_get_init_fn_sect_ptr(void) {
  return _jove_get_init_fn_sect_ptr();
}

bool _jove_see_through_tramp(const void *ptr, uintptr_t *out) {
  return false;
}
