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
  __asm__("mov x0, x0\n"
          : // OutputOperands
          : // InputOperands
          : // Clobbers
          );
}

void __jove_thunk_in() {
  __asm__("mov x0, x0\n"
          : // OutputOperands
          : // InputOperands
          : // Clobbers
          );
}

void __jove_thunk_in_epilogue() {
  __asm__("mov x0, x0\n"
          : // OutputOperands
          : // InputOperands
          : // Clobbers
          );
}

void __jove_thunk_out(thunk_proc_ty dst) {
  __jove_thunk_buff = dst;
  __jove_thunk_out_prologue1();
}

void __jove_thunk_out_prologue1() {
  __asm__("mov x0, x0\n"
          : // OutputOperands
          : // InputOperands
          : // Clobbers
          );
}

void __jove_thunk_out_prologue2() {
  __asm__("mov x0, x0\n"
          : // OutputOperands
          : // InputOperands
          : // Clobbers
          );
}

void __jove_thunk_out_epilogue() {
  __asm__("mov x0, x0\n"
          : // OutputOperands
          : // InputOperands
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
