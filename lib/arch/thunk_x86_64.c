#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg.h"

static CPUX86State cpu_state;

static uint64_t __jove_thunk_in_to;
void __jove_thunk_in_begin(void) __attribute__((naked));

void __jove_thunk_in_begin() {
  __asm__ volatile(
      "movq %%rax, %[out_rax]\n"
      "movq %%rbx, %[out_rbx]\n"
      "movq %%rcx, %[out_rcx]\n"
      "movq %%rdx, %[out_rdx]\n"
      "movq %%rsi, %[out_rsi]\n"
      "movq %%rdi, %[out_rdi]\n"
      "movq %%rbp, %[out_rbp]\n"
      "movq %%rsp, %[out_rsp]\n"
      "movq %%r8, %[out_r8]\n"
      "movq %%r9, %[out_r9]\n"
      "movq %%r10, %[out_r10]\n"
      "movq %%r11, %[out_r11]\n"
      "movq %%r12, %[out_r12]\n"
      "movq %%r13, %[out_r13]\n"
      "movq %%r14, %[out_r14]\n"
      "movq %%r15, %[out_r15]\n"

      "call *%[to]\n"

      "movq %[in_rax], %%rax\n"
      "movq %[in_rbx], %%rbx\n"
      "movq %[in_rcx], %%rcx\n"
      "movq %[in_rdx], %%rdx\n"
      "movq %[in_rsi], %%rsi\n"
      "movq %[in_rdi], %%rdi\n"
      "movq %[in_rbp], %%rbp\n"
      "movq %[in_rsp], %%rsp\n"
      "movq %[in_r8],  %%r8\n"
      "movq %[in_r9],  %%r9\n"
      "movq %[in_r10], %%r10\n"
      "movq %[in_r11], %%r11\n"
      "movq %[in_r12], %%r12\n"
      "movq %[in_r13], %%r13\n"
      "movq %[in_r14], %%r14\n"
      "movq %[in_r15], %%r15\n"

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
      [in_rax] "m" (cpu_state.regs[R_EAX]),
      [in_rbx] "m" (cpu_state.regs[R_EBX]),
      [in_rcx] "m" (cpu_state.regs[R_ECX]),
      [in_rdx] "m" (cpu_state.regs[R_EDX]),
      [in_rsi] "m" (cpu_state.regs[R_ESI]),
      [in_rdi] "m" (cpu_state.regs[R_EDI]),
      [in_rbp] "m" (cpu_state.regs[R_EBP]),
      [in_rsp] "m" (cpu_state.regs[R_ESP]),
      [in_r8] "m"  (cpu_state.regs[8]),
      [in_r9] "m"  (cpu_state.regs[9]),
      [in_r10] "m" (cpu_state.regs[10]),
      [in_r11] "m" (cpu_state.regs[11]),
      [in_r12] "m" (cpu_state.regs[12]),
      [in_r13] "m" (cpu_state.regs[13]),
      [in_r14] "m" (cpu_state.regs[14]),
      [in_r15] "m" (cpu_state.regs[15]),

      [to] "m"(__jove_thunk_in_to)

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
