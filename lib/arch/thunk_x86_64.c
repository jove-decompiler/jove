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

typedef void (*thunk_proc_ty)(void);
static thunk_proc_ty __jove_thunk_in_to;

static uint64_t regbuff[16];

void get_rand(void) __attribute__((naked));
int __jove_impl_get_rand(void);
void __jove_thunk_in_begin(void) __attribute__((naked));

typedef int (*__jove_impl_get_rand_ty)(void);
static const __jove_impl_get_rand_ty __jove_impl_get_rand_addr =
    __jove_impl_get_rand;

__attribute__((naked)) void get_rand(void) {
  __asm__ volatile(
      "movq %%rax, %[out_rax]\n"

      : // OutputOperands
      [out_rax] "=m" (regbuff[R_EAX])

      : // InputOperands

      : // Clobbers
      );

  __asm__ volatile(
      "movq %[__jove_impl], %[thunk_in_to]\n"
      "jmp __jove_thunk_in_begin\n"

      : // OutputOperands
      [thunk_in_to] "=m" (__jove_thunk_in_to)

      : // InputOperands
      [__jove_impl] "a" (__jove_impl_get_rand)

      : // Clobbers
      "rax");
}

void __jove_thunk_in_begin() {
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

      //
      // efficiently copy local copy of regs to CPU state
      //

      "movq %[in_rax], %%rax\n"

      "call *%[in_proc]\n"

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
      "xchgq %[in_rbp], %%rbp\n"
      "xchgq %[in_rsp], %%rsp\n"

      : // OutputOperands
#if 0
      [out_rax] "=m" (regbuff[R_EAX]),
#endif
      [out_rbx] "=m" (regbuff[R_EBX]),
      [out_rcx] "=m" (regbuff[R_ECX]),
      [out_rdx] "=m" (regbuff[R_EDX]),
      [out_rsi] "=m" (regbuff[R_ESI]),
      [out_rdi] "=m" (regbuff[R_EDI]),
      [out_rbp] "=m" (regbuff[R_EBP]),
      [out_rsp] "=m" (regbuff[R_ESP]),
      [out_r8]  "=m" (regbuff[8]),
      [out_r9]  "=m" (regbuff[9]),
      [out_r10] "=m" (regbuff[10]),
      [out_r11] "=m" (regbuff[11]),
      [out_r12] "=m" (regbuff[12]),
      [out_r13] "=m" (regbuff[13]),
      [out_r14] "=m" (regbuff[14]),
      [out_r15] "=m" (regbuff[15])

      : // InputOperands
      [in_rax] "m" (regbuff[R_EAX]),
      [in_rbx] "m" (regbuff[R_EBX]),
      [in_rcx] "m" (regbuff[R_ECX]),
      [in_rdx] "m" (regbuff[R_EDX]),
      [in_rsi] "m" (regbuff[R_ESI]),
      [in_rdi] "m" (regbuff[R_EDI]),
      [in_rbp] "m" (regbuff[R_EBP]),
      [in_rsp] "m" (regbuff[R_ESP]),
      [in_r8] "m"  (regbuff[8]),
      [in_r9] "m"  (regbuff[9]),
      [in_r10] "m" (regbuff[10]),
      [in_r11] "m" (regbuff[11]),
      [in_r12] "m" (regbuff[12]),
      [in_r13] "m" (regbuff[13]),
      [in_r14] "m" (regbuff[14]),
      [in_r15] "m" (regbuff[15]),

      [in_proc] "m" (__jove_thunk_in_to)

      : // Clobbers
      "rax",
      "rbx",
      "rcx",
      "rdx",
      "rsi",
      "rdi",
      "rbp",
      "rsp",
      "r8",
      "r9",
      "r10",
      "r11",
      "r12",
      "r13",
      "r14",
      "r15");
}

void __jove_thunk_in_middle() {
  memcpy(cpu_state.regs, regbuff, sizeof(regbuff));
}

__jove_thunk_in_end() {
  __jove_thunk_in_to();
}

int __jove_impl_get_rand(void) {
  return rand();
}
