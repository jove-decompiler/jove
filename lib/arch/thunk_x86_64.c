#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg.h"
#include <stdio.h>
#include <stdlib.h>

extern CPUX86State cpu_state;
static uint64_t save_buff1, save_buff2;

static CPUX86State* const cpu_state_ptr = &cpu_state;

typedef void (*thunk_proc_ty)(void);
static thunk_proc_ty __jove_thunk_buff;

void get_rand(void) __attribute__((naked));
void __jove_thunk_in(void) __attribute__((naked));

void __jove_thunk_out(thunk_proc_ty);
void __jove_thunk_prologue(void) __attribute__((naked));
void __jove_thunk_out_epilogue(void) __attribute__((naked));

int __jove_impl_get_rand(void);

__attribute__((naked)) void get_rand(void) {
  __asm__("movq %%rax, %[save_buff1]\n"

          : // OutputOperands
          [save_buff1] "=m"(save_buff1)

          : // InputOperands

          : // Clobbers
          );

  __asm__("movq %[__jove_impl], %[thunk_buff]\n"
          "jmp __jove_thunk_in\n"

          : // OutputOperands
          [thunk_buff] "=m"(__jove_thunk_buff)

          : // InputOperands
          [__jove_impl] "a"(__jove_impl_get_rand)

          : // Clobbers
          );
}

/*
 * #define R_EAX 0
 * #define R_ECX 1
 * #define R_EDX 2
 * #define R_EBX 3
 * #define R_ESP 4
 * #define R_EBP 5
 * #define R_ESI 6
 * #define R_EDI 7
 * #define R_8   8
 * #define R_9   9
 * #define R_10  10
 * #define R_11  11
 * #define R_12  12
 * #define R_13  14
 * #define R_14  14
 * #define R_15  15
 */

void __jove_thunk_in() {
  __asm__("movq %%rax, %[saved]\n"
          "movq %[regs_ptr], %%rax\n"

          "movq  %%rcx,  8 (%%rax)\n"
          "movq  %%rdx,  16(%%rax)\n"
          "movq  %%rbx,  24(%%rax)\n"
          "xchgq %%rsp,  32(%%rax)\n"
          "xchgq %%rbp,  40(%%rax)\n"
          "movq  %%rsi,  48(%%rax)\n"
          "movq  %%rdi,  56(%%rax)\n"
          "movq  %%r8,   64(%%rax)\n"
          "movq  %%r9,   72(%%rax)\n"
          "movq  %%r10,  80(%%rax)\n"
          "movq  %%r11,  88(%%rax)\n"
          "movq  %%r12,  96(%%rax)\n"
          "movq  %%r13,  104(%%rax)\n"
          "movq  %%r14,  112(%%rax)\n"
          "movq  %%r15,  120(%%rax)\n"

          "movq %[saved], %%r11\n"
          "movq %%r11,   (%%rax)\n"

          "callq *%[thunk_buff]\n"

          "movq %%rax, %[saved]\n"
          "movq %[regs_ptr], %%rax\n"

          "movq   8(%%rax),  %%rcx\n"
          "movq   16(%%rax), %%rdx\n"
          "movq   24(%%rax), %%rbx\n"
          "xchgq  32(%%rax), %%rsp\n"
          "xchgq  40(%%rax), %%rbp\n"
          "movq   48(%%rax), %%rsi\n"
          "movq   56(%%rax), %%rdi\n"
          "movq   64(%%rax), %%r8\n"
          "movq   72(%%rax), %%r9\n"
          "movq   80(%%rax), %%r10\n"
          "movq   88(%%rax), %%r11\n"
          "movq   96(%%rax), %%r12\n"
          "movq  104(%%rax), %%r13\n"
          "movq  112(%%rax), %%r14\n"
          "movq  120(%%rax), %%r15\n"

          "movq %[saved], %%rax\n"
          "ret\n"
          : // OutputOperands
          [saved] "=m"(save_buff1)
          : // InputOperands
          [saved] "m"(save_buff1),
          [thunk_buff] "m"(__jove_thunk_buff),
          [regs_ptr] "m"(cpu_state_ptr)
          : // Clobbers
          );
}

void __jove_thunk_out(thunk_proc_ty dst) {
  __jove_thunk_buff = dst;

  // change return address to __jove_thunk_out_epilogue
  *((uint64_t*)cpu_state.regs[R_ESP]) = (uint64_t)__jove_thunk_out_epilogue;

  __jove_thunk_prologue();
}

void __jove_thunk_prologue() {
  __asm__("movq %[regs_ptr], %%rax\n"

          "movq   8(%%rax),  %%rcx\n"
          "movq   16(%%rax), %%rdx\n"
          "movq   24(%%rax), %%rbx\n"
          "xchgq  32(%%rax), %%rsp\n"
          "xchgq  40(%%rax), %%rbp\n"
          "movq   48(%%rax), %%rsi\n"
          "movq   56(%%rax), %%rdi\n"
          "movq   64(%%rax), %%r8\n"
          "movq   72(%%rax), %%r9\n"
          "movq   80(%%rax), %%r10\n"
          "movq   88(%%rax), %%r11\n"
          "movq   96(%%rax), %%r12\n"
          "movq  104(%%rax), %%r13\n"
          "movq  112(%%rax), %%r14\n"
          "movq  120(%%rax), %%r15\n"
          "movq     (%%rax), %%rax\n"

          "jmp *%[thunk_buff]\n"

          : // OutputOperands
          : // InputOperands
          [regs_ptr] "m"(cpu_state_ptr),
          [thunk_buff] "m"(__jove_thunk_buff)
          : // Clobbers
          );
}

void __jove_thunk_out_epilogue() {
  __asm__("movq %%rax, %[saved]\n"
          "movq %[regs_ptr], %%rax\n"

          "movq  %%rcx,  8 (%%rax)\n"
          "movq  %%rdx,  16(%%rax)\n"
          "movq  %%rbx,  24(%%rax)\n"
          "xchgq %%rsp,  32(%%rax)\n"
          "xchgq %%rbp,  40(%%rax)\n"
          "movq  %%rsi,  48(%%rax)\n"
          "movq  %%rdi,  56(%%rax)\n"
          "movq  %%r8,   64(%%rax)\n"
          "movq  %%r9,   72(%%rax)\n"
          "movq  %%r10,  80(%%rax)\n"
          "movq  %%r11,  88(%%rax)\n"
          "movq  %%r12,  96(%%rax)\n"
          "movq  %%r13,  104(%%rax)\n"
          "movq  %%r14,  112(%%rax)\n"
          "movq  %%r15,  120(%%rax)\n"

          "movq %[saved], %%r11\n"
          "movq %%r11,   (%%rax)\n"

          "ret\n"

          : // OutputOperands
          [saved] "=m"(save_buff1)
          : // InputOperands
          [saved] "m"(save_buff1), [regs_ptr] "m"(cpu_state_ptr),
          [thunk_buff] "m"(__jove_thunk_buff)
          : // Clobbers
          );
}

int __jove_impl_get_rand(void) {
  return rand();
}
