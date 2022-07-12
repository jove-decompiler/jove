#include "cpu_state.h"
#include <stddef.h>

extern /* __thread */ struct CPUX86State __jove_env;
static /* __thread */ struct CPUX86State *__jove_env_clunk = &__jove_env;

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

#define JOVE_SYS_ATTR _NOINL _HIDDEN
#include "jove_sys.h"

typedef uint64_t jove_thunk_return_t;

_REGPARM _NAKED jove_thunk_return_t _jove_thunk0(uint32_t dstpc,
                                                 uint32_t *emuspp);

_REGPARM _NAKED jove_thunk_return_t _jove_thunk1(uint32_t eax,
                                                 uint32_t dstpc,
                                                 uint32_t *emuspp);

_REGPARM _NAKED jove_thunk_return_t _jove_thunk2(uint32_t eax,
                                                 uint32_t edx,
                                                 uint32_t dstpc,
                                                 uint32_t *emuspp);

_REGPARM _NAKED jove_thunk_return_t _jove_thunk3(uint32_t eax,
                                                 uint32_t edx,
                                                 uint32_t ecx,
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
_HIDDEN void _jove_begin(uint32_t sp_addr);

_HIDDEN unsigned long _jove_thread_init(unsigned long clone_newsp);

_REGPARM _NAKED _HIDDEN void _jove_init(uint32_t eax,
                                        uint32_t edx,
                                        uint32_t ecx);

//
// XXX hack for glibc 2.32+
//
_REGPARM _NAKED _HIDDEN void _jove__libc_early_init(uint32_t eax,
                                                    uint32_t edx,
                                                    uint32_t ecx);

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

unsigned long _jove_thread_init(unsigned long clone_newsp) {
  //
  // initialize CPUState
  //
  __jove_env_clunk->df = 1;

  //
  // setup the emulated stack
  //
  unsigned long env_stack_beg = _jove_alloc_stack();
  unsigned long env_stack_end = env_stack_beg + JOVE_STACK_SIZE;

  unsigned long env_sp = env_stack_end - JOVE_PAGE_SIZE - 16;

  _memcpy((void *)env_sp , (void *)clone_newsp, 16);

  return env_sp;
}

void _jove_begin(target_ulong sp_addr) {
  //
  // setup the stack
  //
  {
    unsigned len = _get_stack_end() - sp_addr;

    unsigned long env_stack_beg = _jove_alloc_stack();
    unsigned long env_stack_end = env_stack_beg + JOVE_STACK_SIZE;

    char *env_sp = (char *)(env_stack_end - JOVE_PAGE_SIZE - len);

    _memcpy(env_sp, (void *)sp_addr, len);

    __jove_env_clunk->regs[R_ESP] = (target_ulong)env_sp;
  }

  _jove_initialize();

  return _jove_call_entry();
}

jove_thunk_return_t _jove_thunk0(uint32_t dstpc,  /* eax */
                                 uint32_t *emuspp /* edx */) {
  asm volatile("pushl %%ebp\n" /* callee-saved registers */
               "pushl %%edi\n"

               "movl %%esp, %%ebp\n" /* save sp in ebp */

               "movl %%edx, %%edi\n" /* emuspp in edi */

               "movl (%%edx), %%esp\n" /* sp=*emusp */
               "movl $0, (%%edx)\n" /* *emusp=0x0 */

               /* args: nothing to do */

               "addl $4, %%esp\n" /* replace return address on the stack */
               "call *%%eax\n"   /* call dstpc */

               "movl %%esp, (%%edi)\n" /* store modified emusp */
               "movl %%ebp, %%esp\n"   /* restore stack pointer */

               "popl %%edi\n" /* callee-saved registers */
               "popl %%ebp\n"
               "ret\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk1(uint32_t eax,
                                 uint32_t dstpc,  /* edx */
                                 uint32_t *emuspp /* ecx */) {
  asm volatile("pushl %%ebp\n" /* callee-saved registers */
               "pushl %%edi\n"

               "movl %%esp, %%ebp\n" /* save sp in ebp */

               "movl %%ecx, %%edi\n" /* emuspp in edi */

               "movl (%%ecx), %%esp\n" /* sp=*emusp */
               "movl $0, (%%ecx)\n" /* *emusp=0x0 */

               /* args: nothing to do */

               "addl $4, %%esp\n" /* replace return address on the stack */
               "call *%%edx\n"   /* call dstpc */

               "movl %%esp, (%%edi)\n" /* store modified emusp */
               "movl %%ebp, %%esp\n"   /* restore stack pointer */

               "popl %%edi\n" /* callee-saved registers */
               "popl %%ebp\n"
               "ret\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk2(uint32_t eax,
                                 uint32_t edx,
                                 uint32_t dstpc,  /* ecx */
                                 uint32_t *emuspp) {
  asm volatile("pushl %%ebp\n" /* callee-saved registers */
               "pushl %%edi\n"

               "movl %%esp, %%ebp\n" /* save sp in ebp */

               "movl 12(%%esp), %%edi\n" /* emuspp in edi */

               "movl (%%edi), %%esp\n" /* sp=*emusp */
               "movl $0, (%%edi)\n" /* *emusp=0x0 */

               /* args: nothing to do */

               "addl $4, %%esp\n" /* replace return address on the stack */
               "call *%%ecx\n"   /* call dstpc */

               "movl %%esp, (%%edi)\n" /* store modified emusp */
               "movl %%ebp, %%esp\n"   /* restore stack pointer */

               "popl %%edi\n" /* callee-saved registers */
               "popl %%ebp\n"
               "ret\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk3(uint32_t eax,
                                 uint32_t edx,
                                 uint32_t ecx,
                                 uint32_t dstpc,
                                 uint32_t *emuspp) {
  asm volatile("pushl %%ebp\n" /* callee-saved registers */
               "pushl %%edi\n"
               "pushl %%esi\n"

               "movl %%esp, %%ebp\n" /* save sp in ebp */

               "movl 16(%%esp), %%esi\n" /* dstpc in esi */
               "movl 20(%%esp), %%edi\n" /* emuspp in edi */

               "movl (%%edi), %%esp\n" /* sp=*emusp */
               "movl $0, (%%edi)\n" /* *emusp=0x0 */

               /* args: nothing to do */

               "addl $4, %%esp\n" /* replace return address on the stack */
               "call *%%esi\n"   /* call dstpc */

               "movl %%esp, (%%edi)\n" /* store modified emusp */
               "movl %%ebp, %%esp\n"   /* restore stack pointer */

               "popl %%esi\n" /* callee-saved registers */
               "popl %%edi\n"
               "popl %%ebp\n"
               "ret\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

void _jove_init(uint32_t eax,
                uint32_t edx,
                uint32_t ecx /* TODO preserve */) {
  asm volatile("pushl %%eax\n" /* preserve arguments */
               "pushl %%edx\n"

               "call _jove_initialize\n"
               "call _jove_get_init_fn_sect_ptr\n"
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
void _jove__libc_early_init(uint32_t eax,
                            uint32_t edx,
                            uint32_t ecx /* TODO preserve */) {
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
