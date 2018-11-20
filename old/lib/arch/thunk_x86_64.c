#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg.h"
#include <stdio.h>
#include <stdlib.h>

extern CPUX86State cpu_state;
static uint64_t savbuf1;
static uint64_t savbuf2;

static uint64_t ret_stack[0x100];
static uint64_t* ret_stack_top = ret_stack;

static CPUX86State* const cpu_state_ptr = &cpu_state;

typedef void (*thunk_proc_ty)(void);
static thunk_proc_ty __jove_thunk_buff;

void __jove_exported_template_fn(void) __attribute__((naked));
void __jove_exported_template_fn_impl(void);

void __jove_thunk_in(void) __attribute__((naked));
void __jove_thunk_out(thunk_proc_ty);
static void __jove_thunk_out_prologue(void) __attribute__((naked));
static void __jove_thunk_out_epilogue(void) __attribute__((naked));

void __jove_exported_template_fn(void) {
  __asm__("movq %%rax, %[savbuf1]\n"

          : // OutputOperands
          [savbuf1] "=m"(savbuf1)

          : // InputOperands

          : // Clobbers
          );

  __asm__("movq %[__jove_impl], %[thunk_buff]\n"
          "jmp __jove_thunk_in\n"

          : // OutputOperands
          [thunk_buff] "=m"(__jove_thunk_buff)

          : // InputOperands
          [__jove_impl] "a"(__jove_exported_template_fn_impl)

          : // Clobbers
          );
}

void __jove_exported_template_fn_impl() {
  __builtin_unreachable();
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
  __asm__("movq %[regs_ptr], %%rax\n"

          "movq  %%rcx,   8(%%rax)\n"
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
          "movq  %%r13, 104(%%rax)\n"
          "movq  %%r14, 112(%%rax)\n"
          "movq  %%r15, 120(%%rax)\n"

          "movq %[saved], %%r11\n"
          "movq %%r11, (%%rax)\n"

          "callq *%[thunk_buff]\n"

          "movq %%rax, %[saved]\n"
          "movq %[regs_ptr], %%rax\n"

          "movq    8(%%rax), %%rcx\n"
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

          // the translated code already pop'd the return address off the stack.
          // we need to undo that.
          "subq $8, %%rsp\n"
          "ret\n"
          : // OutputOperands
          [saved] "=m"(savbuf1)
          : // InputOperands
          [saved] "m"(savbuf1),
          [thunk_buff] "m"(__jove_thunk_buff),
          [regs_ptr] "m"(cpu_state_ptr)
          : // Clobbers
          );
}

void __jove_thunk_out(thunk_proc_ty dst) {
  __jove_thunk_buff = dst;

  // switcheroo the return address. necessary to switch it back for tail calls.
  *ret_stack_top++ = *((uint64_t*)cpu_state.regs[R_ESP]);
  *((uint64_t*)cpu_state.regs[R_ESP]) = (uint64_t)__jove_thunk_out_epilogue;

  __jove_thunk_out_prologue();
}

void __jove_thunk_out_prologue() {
  __asm__("movq %[regs_ptr], %%r11\n"

          "xchgq    (%%r11), %%rax\n"
          "xchgq   8(%%r11), %%rcx\n"
          "xchgq  16(%%r11), %%rdx\n"
          "xchgq  24(%%r11), %%rbx\n"
          "xchgq  32(%%r11), %%rsp\n"
          "xchgq  40(%%r11), %%rbp\n"
          "xchgq  48(%%r11), %%rsi\n"
          "xchgq  56(%%r11), %%rdi\n"
          "xchgq  64(%%r11), %%r8\n"
          "xchgq  72(%%r11), %%r9\n"
          "xchgq  80(%%r11), %%r10\n"
          "xchgq  96(%%r11), %%r12\n"
          "xchgq 104(%%r11), %%r13\n"
          "xchgq 112(%%r11), %%r14\n"
          "xchgq 120(%%r11), %%r15\n"
          "movq   88(%%r11), %%r11\n"

          "jmp *%[thunk_buff]\n"

          : // OutputOperands
          : // InputOperands
          [regs_ptr] "m"(cpu_state_ptr),
          [thunk_buff] "m"(__jove_thunk_buff)
          : // Clobbers
          );
}

void __jove_thunk_out_epilogue() {
  __asm__("movq %%r10, %[r10_save]\n"
          "movq %%r11, %[r11_save]\n"

          // get original return address
          "movq %[ret_stack_top], %%r10\n"
          "subq $8, %%r10\n"
          "movq (%%r10), %%r11\n"

          // pop return address stack
          "movq %%r10, %[ret_stack_top]\n"

          // set original return address
          "movq %%r11, -8(%%rsp)\n"

          // context-switch
          "movq %[regs_ptr], %%r11\n"
          "xchgq %%rax,    (%%r11)\n"
          "xchgq %%rcx,   8(%%r11)\n"
          "xchgq %%rdx,  16(%%r11)\n"
          "xchgq %%rbx,  24(%%r11)\n"
          "xchgq %%rsp,  32(%%r11)\n"
          "xchgq %%rbp,  40(%%r11)\n"
          "xchgq %%rsi,  48(%%r11)\n"
          "xchgq %%rdi,  56(%%r11)\n"
          "xchgq %%r8,   64(%%r11)\n"
          "xchgq %%r9,   72(%%r11)\n"
          "xchgq %%r12,  96(%%r11)\n"
          "xchgq %%r13, 104(%%r11)\n"
          "xchgq %%r14, 112(%%r11)\n"
          "xchgq %%r15, 120(%%r11)\n"

          "movq %[r11_save], %%r10\n"
          "movq %%r10,  88(%%r11)\n"

          "movq %[r10_save], %%r10\n"
          "xchgq %%r10,  80(%%r11)\n"

          "ret\n"

          : // OutputOperands
          [r10_save] "=m"(savbuf1),
          [r11_save] "=m"(savbuf2),
          [ret_stack_top] "=m"(ret_stack_top)
          : // InputOperands
          [r10_save] "m"(savbuf1),
          [r11_save] "m"(savbuf2),
          [regs_ptr] "m"(cpu_state_ptr),
          [ret_stack_top] "m"(ret_stack_top)
          : // Clobbers
          );
}
