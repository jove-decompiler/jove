#include "cpu_state.h"

#include "jove.common.h"

typedef unsigned __int128 jove_thunk_return_t;

#include "jove.common.c"

_HIDDEN
void _jove_begin(uintptr_t rdi,
                 uintptr_t rsi,
                 uintptr_t rdx,
                 uintptr_t rcx,
                 uintptr_t r8,
                 uintptr_t init_sp /* formerly r9 */) {
  _jove_initialize();

  struct CPUArchState *const env = JOVE_RT_THREAD_GLOBALP(env);

  env->regs[R_EDI] = rdi;
  env->regs[R_ESI] = rsi;
  env->regs[R_EDX] = rdx;
  env->regs[R_ECX] = rcx;
  env->regs[R_R8] = r8;
  env->regs[R_ESP] = _jove_begin_setup_emulated_stack(init_sp);

  _jove_call_entry();
}

#define JOVE_THUNK_PROLOGUE                                                    \
  "pushq %%rbp\n\t"                                                            \
  ".cfi_adjust_cfa_offset 8\n"                                                 \
  ".cfi_rel_offset %%rbp,0\n"                                                  \
  "movq %%rsp,%%rbp\n\t"                                                       \
  ".cfi_def_cfa_register %%rbp\n"                                              \
  "pushq %%r15\n" /* callee-saved registers */                                 \
  ".cfi_rel_offset %%r15,-8\n"                                                 \
  "pushq %%r14\n"                                                              \
  ".cfi_rel_offset %%r14,-16\n"

#define JOVE_THUNK_EPILOGUE                                                    \
  "popq %%r14\n" /* callee-saved registers */                                  \
  ".cfi_same_value %%r14\n"                                                    \
  "popq %%r15\n"                                                               \
  ".cfi_same_value %%r15\n"                                                    \
  ".cfi_def_cfa_register %%rsp\n"                                              \
  "popq %%rbp\n\t"                                                             \
  ".cfi_adjust_cfa_offset -8\n"                                                \
  ".cfi_same_value %%rbp\n"                                                    \
  "retq\n"

#define JOVE_THUNK_EXTRA_ARGS                                                  \
  "movsd 832(%%r14),%%xmm0\n"  /* env.xmm_regs[0]._x_ZMMReg[0]._q_XMMReg[0] */ \
  "movsd 896(%%r14),%%xmm1\n"  /* env.xmm_regs[1]._x_ZMMReg[0]._q_XMMReg[0] */ \
  "movsd 960(%%r14),%%xmm2\n"  /* env.xmm_regs[2]._x_ZMMReg[0]._q_XMMReg[0] */ \
  "movsd 1024(%%r14),%%xmm3\n" /* env.xmm_regs[3]._x_ZMMReg[0]._q_XMMReg[0] */ \
  "movsd 1088(%%r14),%%xmm4\n" /* env.xmm_regs[4]._x_ZMMReg[0]._q_XMMReg[0] */ \
  "movsd 1152(%%r14),%%xmm5\n" /* env.xmm_regs[5]._x_ZMMReg[0]._q_XMMReg[0] */ \
  "movsd 1216(%%r14),%%xmm6\n" /* env.xmm_regs[6]._x_ZMMReg[0]._q_XMMReg[0] */ \
  "movsd 1280(%%r14),%%xmm7\n" /* env.xmm_regs[7]._x_ZMMReg[0]._q_XMMReg[0] */ \
                                                                               \
  "movq -32(%%r14),%%rax\n" /* env.regs[R_EAX] */

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

jove_thunk_return_t _jove_thunk0(uintptr_t dstpc   /* rdi */,
                                 uintptr_t *emuspp /* rsi */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%rdi, %%r11\n" /* dstpc in r11 */
               "movq %%rsi, %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk1(uintptr_t rdi,
                                 uintptr_t dstpc   /* rsi */,
                                 uintptr_t *emuspp /* rdx */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%rsi, %%r11\n" /* dstpc in r11 */
               "movq %%rdx, %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk2(uintptr_t rdi,
                                 uintptr_t rsi,
                                 uintptr_t dstpc   /* rdx */,
                                 uintptr_t *emuspp /* rcx */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%rdx, %%r11\n" /* dstpc in r11 */
               "movq %%rcx, %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk3(uintptr_t rdi,
                                 uintptr_t rsi,
                                 uintptr_t rdx,
                                 uintptr_t dstpc   /* rcx */,
                                 uintptr_t *emuspp /* r8 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%rcx, %%r11\n" /* dstpc in r11 */
               "movq %%r8, %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk4(uintptr_t rdi,
                                 uintptr_t rsi,
                                 uintptr_t rdx,
                                 uintptr_t rcx,
                                 uintptr_t dstpc   /* r8 */,
                                 uintptr_t *emuspp /* r9 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%r8, %%r11\n" /* dstpc in r11 */
               "movq %%r9, %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk5(uintptr_t rdi,
                                 uintptr_t rsi,
                                 uintptr_t rdx,
                                 uintptr_t rcx,
                                 uintptr_t r8,
                                 uintptr_t dstpc   /* r9 */,
                                 uintptr_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq %%r9, %%r11\n" /* dstpc in r11 */
               "movq 32(%%rsp), %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk6(uintptr_t rdi,
                                 uintptr_t rsi,
                                 uintptr_t rdx,
                                 uintptr_t rcx,
                                 uintptr_t r8,
                                 uintptr_t r9,
                                 uintptr_t dstpc,
                                 uintptr_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "movq 32(%%rsp), %%r11\n" /* dstpc in r11 */
               "movq 40(%%rsp), %%r14\n" /* emuspp in r14 */

               JOVE_THUNK_CORE

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

#undef JOVE_THUNK_PROLOGUE
#undef JOVE_THUNK_EPILOGUE

_HIDDEN
_NAKED
void _jove_init(uintptr_t rdi,
                uintptr_t rsi,
                uintptr_t rdx,
                uintptr_t rcx,
                uintptr_t r8,
                uintptr_t r9) {
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
               "call _jove_do_get_init_fn_sect_ptr\n"
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
_NAKED
_HIDDEN
void _jove__libc_early_init(uintptr_t rdi,
                            uintptr_t rsi,
                            uintptr_t rdx,
                            uintptr_t rcx,
                            uintptr_t r8,
                            uintptr_t r9) {
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

_HIDDEN uintptr_t _jove_do_get_init_fn_sect_ptr(void) {
  return _jove_get_init_fn_sect_ptr();
}

bool _jove_see_through_tramp(const void *ptr, uintptr_t *out) {
  const uint8_t *const u8p = (const uint8_t *)ptr;
  if (!(u8p[0] == 0xff &&
        u8p[1] == 0x25)) /* see importThunkX86 in lld/COFF/Chunks.h */
    return false;

  //
  // 140006ab0: ff 25 ba 7c 00 00            jmpq    *0x7cba(%rip)           # 0x14000e770 <__imp__configure_narrow_argv>
  //
  const unsigned sizeof_jmp = 6;
  uint32_t pc_off = *((const uint32_t *)&u8p[2]);

  *out = *((uintptr_t *)(u8p + pc_off + sizeof_jmp));
  return true;
}
