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

#define JOVE_SYS_ATTR _INL _UNUSED
#include "jove_sys.h"

typedef unsigned __int128 jove_thunk_return_t;

_NAKED jove_thunk_return_t _jove_thunk0(uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk1(uint64_t rdi,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk2(uint64_t rdi,
                                        uint64_t rsi,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk3(uint64_t rdi,
                                        uint64_t rsi,
                                        uint64_t rdx,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk4(uint64_t rdi,
                                        uint64_t rsi,
                                        uint64_t rdx,
                                        uint64_t rcx,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk5(uint64_t rdi,
                                        uint64_t rsi,
                                        uint64_t rdx,
                                        uint64_t rcx,
                                        uint64_t r8,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

_NAKED jove_thunk_return_t _jove_thunk6(uint64_t rdi,
                                        uint64_t rsi,
                                        uint64_t rdx,
                                        uint64_t rcx,
                                        uint64_t r8,
                                        uint64_t r9,
                                        uint64_t dstpc,
                                        uint64_t *emuspp);

static uintptr_t _jove_alloc_stack(void);
static void _jove_free_stack(uintptr_t beg);
static uintptr_t _jove_alloc_callstack(void);
static void _jove_free_callstack(uintptr_t start);
static uintptr_t _jove_alloc_large_buffer(void);
static void _jove_free_large_buffer(uintptr_t start);

static bool _jove_see_through_stub(const void *ptr, uintptr_t *out);

#include "jove.llvm.c"
#include "jove.arch.c"
#include "jove.util.c"
#include "jove.common.c"
#include "jove.recover.c"

_HIDDEN
_NAKED void _jove_start(void);
static void _jove_begin(uint64_t rdi,
                        uint64_t rsi,
                        uint64_t rdx,
                        uint64_t rcx,
                        uint64_t r8,
                        uint64_t sp_addr /* formerly r9 */);

_HIDDEN unsigned long _jove_thread_init(unsigned long clone_newsp);

_NAKED _HIDDEN void _jove_init(uint64_t rdi,
                               uint64_t rsi,
                               uint64_t rdx,
                               uint64_t rcx,
                               uint64_t r8,
                               uint64_t r9);

//
// XXX hack for glibc 2.32+
//
_NAKED void _jove__libc_early_init(uint64_t rdi,
                                   uint64_t rsi,
                                   uint64_t rdx,
                                   uint64_t rcx,
                                   uint64_t r8,
                                   uint64_t r9);

void __stdcall mainCRTStartup() {
  //
  // TODO: __getmainargs()
  //
  {
    //unsigned len = _get_stack_end() - sp_addr;
    unsigned len = JOVE_PAGE_SIZE; /* FIXME */

    uintptr_t env_stack_beg = _jove_alloc_stack();
    uintptr_t env_stack_end = env_stack_beg + JOVE_STACK_SIZE;

    uintptr_t emu_sp = env_stack_end - JOVE_PAGE_SIZE - len;

    emu_sp &= ~31UL;
    emu_sp -= 8;

    __jove_env.regs[R_ESP] = emu_sp;
  }

  _jove_initialize();

  return _jove_call_entry();
}

void _jove_start(void) {
  asm volatile(
               /* Clear the frame pointer.  The ABI suggests this be done, to
                 mark the outermost frame obviously.  */
               "xorq %%rbp, %%rbp\n"

               "movq %%rsp, %%r9\n"

               /* Align the stack to a 16 byte boundary to follow the ABI.  */
               "and  $~15, %%rsp\n"
               "call %P0\n"
               "hlt\n" /* Crash if somehow `_jove_begin' does return. */

               : /* OutputOperands */
               : /* InputOperands */
               "i"(_jove_begin)
               : /* Clobbers */);
}

//_HIDDEN uintptr_t _jove_alloc_callstack(void);
//_HIDDEN void _jove_free_callstack(uintptr_t);

unsigned long _jove_thread_init(unsigned long clone_newsp) {
  //
  // initialize CPUState
  //
  __jove_env.df = 1;

  //
  // setup the emulated stack
  //
  unsigned long env_stack_beg = _jove_alloc_stack();
  unsigned long env_stack_end = env_stack_beg + JOVE_STACK_SIZE;

  unsigned long env_sp = env_stack_end - JOVE_PAGE_SIZE - 16;

  _memcpy((void *)env_sp , (void *)clone_newsp, 16);

  return env_sp;
}

void _jove_begin(uint64_t rdi,
                 uint64_t rsi,
                 uint64_t rdx,
                 uint64_t rcx,
                 uint64_t r8,
                 uint64_t init_sp /* formerly r9 */) {
  __jove_env.regs[R_EDI] = rdi;
  __jove_env.regs[R_ESI] = rsi;
  __jove_env.regs[R_EDX] = rdx;
  __jove_env.regs[R_ECX] = rcx;
  __jove_env.regs[R_R8] = r8;

  //
  // setup the stack
  //
  {
    unsigned len = _get_stack_end() - init_sp;

    uintptr_t emu_stack_beg = _jove_alloc_stack();
    uintptr_t emu_stack_end = emu_stack_beg + JOVE_STACK_SIZE;

    uintptr_t emu_sp = emu_stack_end - JOVE_PAGE_SIZE - len;

    if (init_sp % 16 != 0) _UNREACHABLE("init sp misaligned on entry");
    if (emu_sp % 16 != 0) _UNREACHABLE("emu sp misaligned on entry");

    _memcpy((void *)emu_sp, (void *)init_sp, len);

    __jove_env.regs[R_ESP] = emu_sp;
  }

  _jove_initialize();

  return _jove_call_entry();
}

#define JOVE_THUNK_PROLOGUE                                                    \
  "pushq %%r15\n" /* callee-saved registers */                                 \
  "pushq %%r14\n"

#define JOVE_THUNK_EPILOGUE                                                    \
  "popq %%r14\n" /* callee-saved registers */                                  \
  "popq %%r15\n"                                                               \
  "retq\n"

#define JOVE_THUNK_EXTRA_ARGS                                                  \
  "movsd 832(%%r14),%%xmm0\n"                                                  \
  "movsd 896(%%r14),%%xmm1\n"                                                  \
  "movsd 960(%%r14),%%xmm2\n"                                                  \
  "movsd 1024(%%r14),%%xmm3\n"                                                 \
  "movsd 1088(%%r14),%%xmm4\n"                                                 \
  "movsd 1152(%%r14),%%xmm5\n"                                                 \
  "movsd 1216(%%r14),%%xmm6\n"                                                 \
  "movsd 1280(%%r14),%%xmm7\n"

#define JOVE_THUNK_EXTRA_RETS                                                  \
  "movsd %%xmm0,832(%%r14)\n"                                                  \
  "movsd %%xmm1,896(%%r14)\n"

#define JOVE_THUNK_CORE                                                        \
  JOVE_THUNK_EXTRA_ARGS                                                        \
                                                                               \
  "movq %%rsp, %%r15\n" /* save sp in r15 */                                   \
                                                                               \
  "movq (%%r14), %%rsp\n" /* sp=emusp */                                       \
  "movq $0, (%%r14)\n"    /* emusp=0x0 */                                      \
                                                                               \
  /* args: nothing to do */                                                    \
                                                                               \
  "addq $8, %%rsp\n" /* replace return address on the stack */                 \
  "callq *%%r11\n"   /* call dstpc */                                          \
                                                                               \
  "movq %%rsp, (%%r14)\n" /* store modified emusp */                           \
  "movq %%r15, %%rsp\n"   /* restore stack pointer */                          \
                                                                               \
  JOVE_THUNK_EXTRA_RETS                                                        \
                                                                               \
  JOVE_THUNK_EPILOGUE

jove_thunk_return_t _jove_thunk0(uint64_t dstpc   /* rdi */,
                                 uint64_t *emuspp /* rsi */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%rdi, %%r11\n" /* dstpc in r11 */
               "movq %%rsi, %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk1(uint64_t rdi,
                                 uint64_t dstpc   /* rsi */,
                                 uint64_t *emuspp /* rdx */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%rsi, %%r11\n" /* dstpc in r11 */
               "movq %%rdx, %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk2(uint64_t rdi,
                                 uint64_t rsi,
                                 uint64_t dstpc   /* rdx */,
                                 uint64_t *emuspp /* rcx */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%rdx, %%r11\n" /* dstpc in r11 */
               "movq %%rcx, %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk3(uint64_t rdi,
                                 uint64_t rsi,
                                 uint64_t rdx,
                                 uint64_t dstpc   /* rcx */,
                                 uint64_t *emuspp /* r8 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%rcx, %%r11\n" /* dstpc in r11 */
               "movq %%r8, %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk4(uint64_t rdi,
                                 uint64_t rsi,
                                 uint64_t rdx,
                                 uint64_t rcx,
                                 uint64_t dstpc   /* r8 */,
                                 uint64_t *emuspp /* r9 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%r8, %%r11\n" /* dstpc in r11 */
               "movq %%r9, %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk5(uint64_t rdi,
                                 uint64_t rsi,
                                 uint64_t rdx,
                                 uint64_t rcx,
                                 uint64_t r8,
                                 uint64_t dstpc   /* r9 */,
                                 uint64_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%r9, %%r11\n" /* dstpc in r11 */
               "movq 24(%%rsp), %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk6(uint64_t rdi,
                                 uint64_t rsi,
                                 uint64_t rdx,
                                 uint64_t rcx,
                                 uint64_t r8,
                                 uint64_t r9,
                                 uint64_t dstpc,
                                 uint64_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq 24(%%rsp), %%r11\n" /* dstpc in r11 */
               "movq 32(%%rsp), %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

#undef JOVE_THUNK_PROLOGUE
#undef JOVE_THUNK_EPILOGUE

void _jove_init(uint64_t rdi,
                uint64_t rsi,
                uint64_t rdx,
                uint64_t rcx,
                uint64_t r8,
                uint64_t r9) {
  asm volatile(
               "xchgq %%r15, %%r15\n" /* nop */
               "xchgq %%r14, %%r14\n" /* nop */
               "xchgq %%r13, %%r13\n" /* nop */
               "xchgq %%r12, %%r12\n" /* nop */
               "xchgq %%r11, %%r11\n" /* nop */

               "pushq %%rdi\n" /* preserve arguments */
               "pushq %%rsi\n"
               "pushq %%rdx\n"
               "pushq %%rcx\n"
               "pushq %%r8\n"
               "pushq %%r9\n"

               "call _jove_initialize\n"
               "call _jove_get_init_fn_sect_ptr\n"
               "movq %%rax, %%r11\n"

               "popq %%r9\n" /* preserve arguments */
               "popq %%r8\n"
               "popq %%rcx\n"
               "popq %%rdx\n"
               "popq %%rsi\n"
               "popq %%rdi\n"

               "test %%r11, %%r11\n" /* only call initfn if not-null */
               "je dont_call_initfn\n"

               "jmp *%%r11\n"

               "dont_call_initfn:\n"
               "ret\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

//
// XXX hack for glibc 2.32+
//
void _jove__libc_early_init(uint64_t rdi,
                            uint64_t rsi,
                            uint64_t rdx,
                            uint64_t rcx,
                            uint64_t r8,
                            uint64_t r9) {
  asm volatile("pushq %%rdi\n" /* preserve arguments */
               "pushq %%rsi\n"
               "pushq %%rdx\n"
               "pushq %%rcx\n"
               "pushq %%r8\n"
               "pushq %%r9\n"

               "call _jove_do_call_rt_init\n"
               "call _jove_initialize\n"
               "call _jove_get_libc_early_init_fn_sect_ptr\n"
               "movq %%rax, %%r11\n"

               "popq %%r9\n" /* preserve arguments */
               "popq %%r8\n"
               "popq %%rcx\n"
               "popq %%rdx\n"
               "popq %%rsi\n"
               "popq %%rdi\n"

               "jmp *%%r11\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

extern void _jove_rt_init(void);

_HIDDEN void _jove_do_call_rt_init(void) {
  _jove_rt_init();

  _jove_do_manual_relocations();
  _jove_do_emulate_copy_relocations();
}

bool _jove_see_through_stub(const void *ptr, uintptr_t *out) {
  const uint8_t *const u8p = (const uint8_t *)ptr;
  if (!(u8p[0] == 0xff &&
        u8p[1] == 0x25)) /* see importThunkX86 in lld/COFF/Chunks.h */
    return false;

  //
  // 140006ab0: ff 25 ba 7c 00 00            jmpq    *0x7cba(%rip)           # 0x14000e770 <__imp__configure_narrow_argv>
  //
  const unsigned sizeof_jmp = 6;
  uint32_t pc_off = *((const uint32_t *)&u8p[2]);

  *out = *((uint64_t *)(u8p + pc_off + sizeof_jmp));
  return true;
}
