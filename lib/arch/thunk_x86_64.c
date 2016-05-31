#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg.h"
#include <stdio.h>
#include <stdlib.h>

void foo(int);
void foo(int x) {
  printf("%d\n", x);
}

extern CPUX86State cpu_state;
static uint64_t save_buff;

static CPUX86State* const cpu_state_ptr = &cpu_state;

typedef void (*thunk_proc_ty)(void);
static thunk_proc_ty __jove_thunk_buff;

void get_rand(void) __attribute__((naked));
void __jove_thunk_in(void) __attribute__((naked));

void __jove_thunk_out(void) __attribute__((naked));
void __jove_thunk_out_prologue(void) __attribute__((naked));

int __jove_impl_get_rand(void);

__attribute__((naked)) void get_rand(void) {
  __asm__ (
      "movq %%rax, %[save_buff]\n"

      : // OutputOperands
      [save_buff] "=m" (save_buff)

      : // InputOperands

      : // Clobbers
      );

  __asm__ (
      "movq %[__jove_impl], %[thunk_buff]\n"
      "jmp __jove_thunk_in\n"

      : // OutputOperands
      [thunk_buff] "=m" (__jove_thunk_buff)

      : // InputOperands
      [__jove_impl] "a" (__jove_impl_get_rand)

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
  __asm__ (
      "movq %%rax, %[saved]\n"
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

      "movq  8(%%rax),   %%rcx\n"
      "movq  16(%%rax),  %%rdx\n"
      "movq  24(%%rax),  %%rbx\n"
      "xchgq 32(%%rax),  %%rsp\n"
      "xchgq 40(%%rax),  %%rbp\n"
      "movq  48(%%rax),  %%rsi\n"
      "movq  56(%%rax),  %%rdi\n"
      "movq  64(%%rax),  %%r8\n"
      "movq  72(%%rax),  %%r9\n"
      "movq  80(%%rax),  %%r10\n"
      "movq  88(%%rax),  %%r11\n"
      "movq  96(%%rax),  %%r12\n"
      "movq  104(%%rax), %%r13\n"
      "movq  112(%%rax), %%r14\n"
      "movq  120(%%rax), %%r15\n"

      "movq %[saved], %%rax\n"
      "ret\n"
      : // OutputOperands
      [saved] "=m" (save_buff)
      : // InputOperands
      [saved] "m" (save_buff),
      [thunk_buff] "m" (__jove_thunk_buff),
      [regs_ptr] "m" (cpu_state_ptr)
      : // Clobbers
      );
}

void __jove_thunk_out() {
#if 0
  __asm__ volatile(
      "xchgq %[in_rbp], %%rbp\n"
      "xchgq %[in_rsp], %%rsp\n"

      : // OutputOperands

      : // InputOperands
      [in_rbp] "m" (cpu_state.regs[R_EBP]),
      [in_rsp] "m" (cpu_state.regs[R_ESP])

      : // Clobbers
      "rbp",
      "rsp");

  __asm__ volatile(
      // change return address to __jove_thunk_out_prologue
      "movq %[prologue], (%%rsp)\n"

      : // OutputOperands

      : // InputOperands
      [prologue] "r" (__jove_thunk_out_prologue)

      : // Clobbers
      );

  __asm__ volatile(
      "movq %[in_rax], %%rax\n"
      "movq %[in_rbx], %%rbx\n"
      "movq %[in_rcx], %%rcx\n"
      "movq %[in_rdx], %%rdx\n"
      "movq %[in_rsi], %%rsi\n"
      "movq %[in_rdi], %%rdi\n"
      "movq %[in_r8],  %%r8\n"
      "movq %[in_r9],  %%r9\n"
      "movq %[in_r10], %%r10\n"
      "movq %[in_r11], %%r11\n"
      "movq %[in_r12], %%r12\n"
      "movq %[in_r13], %%r13\n"
      "movq %[in_r14], %%r14\n"
      "movq %[in_r15], %%r15\n"

      "jmp *%[dst]\n"

      : // OutputOperands

      : // InputOperands
      [in_rax] "m" (cpu_state.regs[R_EAX]),
      [in_rbx] "m" (cpu_state.regs[R_EBX]),
      [in_rcx] "m" (cpu_state.regs[R_ECX]),
      [in_rdx] "m" (cpu_state.regs[R_EDX]),
      [in_rsi] "m" (cpu_state.regs[R_ESI]),
      [in_rdi] "m" (cpu_state.regs[R_EDI]),
      [in_r8]  "m" (cpu_state.regs[8]),
      [in_r9]  "m" (cpu_state.regs[9]),
      [in_r10] "m" (cpu_state.regs[10]),
      [in_r11] "m" (cpu_state.regs[11]),
      [in_r12] "m" (cpu_state.regs[12]),
      [in_r13] "m" (cpu_state.regs[13]),
      [in_r14] "m" (cpu_state.regs[14]),
      [in_r15] "m" (cpu_state.regs[15]),

      [dst] "*m" (__jove_thunk_buff)

      : // Clobbers
      "rax",
      "rbx",
      "rcx",
      "rdx",
      "rsi",
      "rdi",
      "r8",
      "r9",
      "r10",
      "r11",
      "r12",
      "r13",
      "r14",
      "r15");
#endif
}

void __jove_thunk_out_prologue() {
#if 0
  __asm__ volatile(
      "xchgq %%rbp, %[out_rbp]\n"
      "xchgq %%rsp, %[out_rsp]\n"
      "movq %%rbx, %[out_rbx]\n"
      "movq %%rcx, %[out_rcx]\n"
      "movq %%rdx, %[out_rdx]\n"
      "movq %%rsi, %[out_rsi]\n"
      "movq %%rdi, %[out_rdi]\n"
      "movq %%r8,  %[out_r8]\n"
      "movq %%r9,  %[out_r9]\n"
      "movq %%r10, %[out_r10]\n"
      "movq %%r11, %[out_r11]\n"
      "movq %%r12, %[out_r12]\n"
      "movq %%r13, %[out_r13]\n"
      "movq %%r14, %[out_r14]\n"
      "movq %%r15, %[out_r15]\n"
      "ret\n"

      : // OutputOperands
      [out_rax] "=m" (cpu_state.regs[R_EAX]),
      [out_rbx] "=m" (cpu_state.regs[R_EBX]),
      [out_rcx] "=m" (cpu_state.regs[R_ECX]),
      [out_rdx] "=m" (cpu_state.regs[R_EDX]),
      [out_rsi] "=m" (cpu_state.regs[R_ESI]),
      [out_rdi] "=m" (cpu_state.regs[R_EDI]),
      [out_rbp] "=m" (cpu_state.regs[R_EBP]),
      [out_rsp] "=m" (cpu_state.regs[R_ESP]),
      [out_r8]  "=m" (cpu_state.regs[8]),
      [out_r9]  "=m" (cpu_state.regs[9]),
      [out_r10] "=m" (cpu_state.regs[10]),
      [out_r11] "=m" (cpu_state.regs[11]),
      [out_r12] "=m" (cpu_state.regs[12]),
      [out_r13] "=m" (cpu_state.regs[13]),
      [out_r14] "=m" (cpu_state.regs[14]),
      [out_r15] "=m" (cpu_state.regs[15])

      : // InputOperands

      : // Clobbers
      );
#endif
}

int __jove_impl_get_rand(void) {
  return rand();
}
