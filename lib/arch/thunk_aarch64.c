#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

extern CPUARMState cpu_state;

typedef void (*thunk_proc_ty)(void);
static thunk_proc_ty __jove_thunk_buff;

void __jove_exported_template_fn(void) __attribute__((naked));
void __jove_exported_template_fn_impl(void) __attribute__((naked));

void __jove_thunk_in(void) __attribute__((naked));
void __jove_thunk_in_epilogue(void) __attribute__((naked));
void __jove_thunk_out(thunk_proc_ty);
static void __jove_thunk_out_prologue1(void) __attribute__((naked));
static void __jove_thunk_out_prologue2(void) __attribute__((naked));
static void __jove_thunk_out_epilogue(void) __attribute__((naked));

void __jove_exported_template_fn(void) {
  __asm__(// save x8 and x9
          "stp x8, x9, [sp, #-16]\n"

          // store address of translated function to x9
          "adr x9, %[fn]\n"

          // jump to __jove_thunk_in
          "b %[__jove_thunk_in]\n"

          : // OutputOperands
          : // InputOperands
          [fn] "X"(__jove_exported_template_fn_impl),
          [__jove_thunk_in] "X"(__jove_thunk_in)
          : // Clobbers
          );
}

void __jove_thunk_in() {
  __asm__(// use x8 to write to CPU state
          "mov x8, %[regs_ptr]\n"

          //
          // transfer regs to CPU state
          //
          "stp x0,  x1,  [x8, #16 * 0]\n"
          "stp x2,  x3,  [x8, #16 * 1]\n"
          "stp x4,  x5,  [x8, #16 * 2]\n"
          "stp x6,  x7,  [x8, #16 * 3]\n"
          "stp x10, x11, [x8, #16 * 5]\n"

          "ldp x10, x11, [sp, #-16]\n" // load x8 and x9
          "stp x10, x11, [x8, #16 * 4]\n" // store x8 and x9

          "stp x12, x13, [x8, #16 * 6]\n"
          "stp x14, x15, [x8, #16 * 7]\n"
          "stp x16, x17, [x8, #16 * 8]\n"
          "stp x18, x19, [x8, #16 * 9]\n"
          "stp x20, x21, [x8, #16 * 10]\n"
          "stp x22, x23, [x8, #16 * 11]\n"
          "stp x24, x25, [x8, #16 * 12]\n"
          "stp x26, x27, [x8, #16 * 13]\n"
          "str x28, [x8, #8 * 28]\n"

          //
          // exchange fp (x29)
          //
          "ldr x10, [x8, #8 * 29]\n"
          "str fp, [x8, #8 * 29]\n"
          "mov fp, x10\n"

          //
          // exchange sp (x31)
          //
          "ldr x11, [x8, #8 * 31]\n"
          "mov x10, sp\n"
          "str x10, [x8, #8 * 31]\n"
          "mov sp, x11\n"

          //
          // sets link register (x30) to return to __jove_thunk_in_epilogue
          //
          "adr lr, %[__jove_thunk_in_epilogue]\n"

          //
          // jump to translated code
          //
          "br x9\n"

          : // OutputOperands
          : // InputOperands
          [regs_ptr] "X"(&cpu_state.xregs[0]),
          [__jove_thunk_in_epilogue] "X"(__jove_thunk_in_epilogue)
          : // Clobbers
          );
}

void __jove_thunk_in_epilogue() {
  __asm__(// use x8 to read from CPU state
          "mov x8, %[regs_ptr]\n"

          "ldp x0,  x1,  [x8, #16 * 0]\n"
          "ldp x2,  x3,  [x8, #16 * 1]\n"
          "ldp x4,  x5,  [x8, #16 * 2]\n"
          "ldp x6,  x7,  [x8, #16 * 3]\n"
          "ldp x10, x11, [x8, #16 * 5]\n"
          "ldp x12, x13, [x8, #16 * 6]\n"
          "ldp x14, x15, [x8, #16 * 7]\n"
          "ldp x16, x17, [x8, #16 * 8]\n"
          "ldp x18, x19, [x8, #16 * 9]\n"
          "ldp x20, x21, [x8, #16 * 10]\n"
          "ldp x22, x23, [x8, #16 * 11]\n"
          "ldp x24, x25, [x8, #16 * 12]\n"
          "ldp x26, x27, [x8, #16 * 13]\n"
          "ldp x28, x29, [x8, #16 * 14]\n"

          //
          // exchange fp (x29)
          //
          "ldr x10, [x8, #8 * 29]\n"
          "str fp, [x8, #8 * 29]\n"
          "mov fp, x10\n"

          //
          // exchange sp (x31)
          //
          "ldr x11, [x8, #8 * 31]\n"
          "mov x10, sp\n"
          "str x10, [x8, #8 * 31]\n"
          "mov sp, x11\n"

          "ldp x8, x9, [x8, #16 * 4]\n" // store x8 and x9

          "ret"

          : // OutputOperands
          : // InputOperands
          [regs_ptr] "X"(&cpu_state.xregs[0])
          : // Clobbers
          );
}

void __jove_thunk_out(thunk_proc_ty dst) {
  __jove_thunk_buff = dst;
  __jove_thunk_out_prologue1();
}

void __jove_thunk_out_prologue1() {
  __asm__(// use x8 to read from CPU state
          "mov x8, %[regs_ptr]\n"

          "ldp x0,  x1,  [x8, #16 * 0]\n"
          "ldp x2,  x3,  [x8, #16 * 1]\n"
          "ldp x4,  x5,  [x8, #16 * 2]\n"
          "ldp x6,  x7,  [x8, #16 * 3]\n"
          "ldp x10, x11, [x8, #16 * 5]\n"
          "ldp x12, x13, [x8, #16 * 6]\n"
          "ldp x14, x15, [x8, #16 * 7]\n"
          "ldp x16, x17, [x8, #16 * 8]\n"
          "ldp x18, x19, [x8, #16 * 9]\n"
          "ldp x20, x21, [x8, #16 * 10]\n"
          "ldp x22, x23, [x8, #16 * 11]\n"
          "ldp x24, x25, [x8, #16 * 12]\n"
          "ldp x26, x27, [x8, #16 * 13]\n"
          "ldp x28, x29, [x8, #16 * 14]\n"

          //
          // exchange fp (x29)
          //
          "ldr x10, [x8, #8 * 29]\n"
          "str fp, [x8, #8 * 29]\n"
          "mov fp, x10\n"

          //
          // exchange sp (x31)
          //
          "ldr x11, [x8, #8 * 31]\n"
          "mov x10, sp\n"
          "str x10, [x8, #8 * 31]\n"
          "mov sp, x11\n"

          "ldr x8, [x8, #16 * 4]\n" // store x8 and x9

          "b %[prologue2]\n"

          : // OutputOperands
          : // InputOperands
          [regs_ptr] "X"(&cpu_state.xregs[0]),
          [prologue2] "X"(__jove_thunk_out_prologue2)
          : // Clobbers
          );
}

void __jove_thunk_out_prologue2() {
  __asm__("adr lr, %[epilogue]\n"
          "mov x8, %[__jove_thunk_buff]\n"
          "br x8"
          : // OutputOperands
          : // InputOperands
          [epilogue] "X"(__jove_thunk_out_epilogue),
          [__jove_thunk_buff] "X"(*__jove_thunk_buff)
          : // Clobbers
          );
}

void __jove_thunk_out_epilogue() {
  __asm__(// save x8 and x9
          "stp x8, x9, [sp, #-16]\n"

          // use x8 to write to CPU state
          "mov x8, %[regs_ptr]\n"

          //
          // transfer regs to CPU state
          //
          "stp x0,  x1,  [x8, #16 * 0]\n"
          "stp x2,  x3,  [x8, #16 * 1]\n"
          "stp x4,  x5,  [x8, #16 * 2]\n"
          "stp x6,  x7,  [x8, #16 * 3]\n"
          "stp x10, x11, [x8, #16 * 5]\n"

          "ldp x10, x11, [sp, #-16]\n" // load x8 and x9
          "stp x10, x11, [x8, #16 * 4]\n" // store x8 and x9

          "stp x12, x13, [x8, #16 * 6]\n"
          "stp x14, x15, [x8, #16 * 7]\n"
          "stp x16, x17, [x8, #16 * 8]\n"
          "stp x18, x19, [x8, #16 * 9]\n"
          "stp x20, x21, [x8, #16 * 10]\n"
          "stp x22, x23, [x8, #16 * 11]\n"
          "stp x24, x25, [x8, #16 * 12]\n"
          "stp x26, x27, [x8, #16 * 13]\n"
          "str x28, [x8, #8 * 28]\n"

          //
          // exchange fp (x29)
          //
          "ldr x10, [x8, #8 * 29]\n"
          "str fp, [x8, #8 * 29]\n"
          "mov fp, x10\n"

          //
          // exchange sp (x31)
          //
          "ldr x11, [x8, #8 * 31]\n"
          "mov x10, sp\n"
          "str x10, [x8, #8 * 31]\n"
          "mov sp, x11\n"

          "ret"
          : // OutputOperands
          : // InputOperands
          [regs_ptr] "X"(&cpu_state.xregs[0])
          : // Clobbers
          );
}

void __jove_exported_template_fn_impl() {
  __asm__("mov x0, x0\n"
          : // OutputOperands
          : // InputOperands
          : // Clobbers
          );
}
