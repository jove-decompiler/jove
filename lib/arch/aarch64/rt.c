#include "cpu_state.h"
#include <stddef.h>

#define _GNU_SOURCE
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

#include "rt.constants.h"
#include "rt.macros.h"
#include "rt.types.h"
#include "rt.common.h"

#include "rt.util.c"
#include "rt.common.c"

void _jove_inverse_thunk(void) {
  asm volatile("sub sp, sp, #128\n"
               "stp x0, x1, [sp, #16]\n" /* preserve return registers */
               "stp x2, x3, [sp, #32]\n"
               "stp x4, x5, [sp, #48]\n"
               "stp x6, x7, [sp, #64]\n"

               "stp x19, x20, [sp, #80]\n" /* callee-saved registers */
               "stp x21, x22, [sp, #96]\n"

               //
               // restore emulated stack pointer
               //
               "bl _jove_emusp_location\n" // x0 = emuspp

               "ldr x19, [x0]\n" // save emusp, we'll need it at the end of this function

               "ldr x1, [sp, #152]\n"  // read saved_emusp off the stack
               "str x1, [x0]\n" // restore emusp

               //
               // free the callstack we allocated in sighandler
               //
               "bl _jove_callstack_begin_location\n"
               "ldr x0, [x0]\n"
               "bl _jove_do_free_callstack\n"

               //
               // restore __jove_callstack
               //
               "bl _jove_callstack_location\n"
               "ldr x1, [sp, #160]\n" // x1 = saved_callstack
               "str x1, [x0]\n" // restore callstack

               //
               // restore __jove_callstack_begin
               //
               "bl _jove_callstack_begin_location\n"
               "ldr x1, [sp, #168]\n" // x1 = saved_callstack_begin
               "str x1, [x0]\n" // restore callstack_begin

               //
               // mark newstack as to be freed
               //
               "ldr x0, [sp, #176]\n" // x0 = newstack
               "bl _jove_do_free_stack_later\n"

               "mov x8, x19\n" /* emusp in scratch reg x8 */

               "ldp x19, x20, [sp, #80]\n" /* callee-saved registers */
               "ldp x21, x22, [sp, #96]\n"

               "ldp x0, x1, [sp, #16]\n" /* return registers */
               "ldp x2, x3, [sp, #32]\n"
               "ldp x4, x5, [sp, #48]\n"
               "ldp x6, x7, [sp, #64]\n"

               "ldr x9, [sp, #136]\n" /* read saved_retaddr into x9 */

               "mov sp, x8\n" /* sp = emusp */
               "br x9\n" /* pc = saved_retaddr */

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

bool is_sigreturn_insn_sequence(const void *insn_bytes) {
  /* FIXME copied from mips */
  const uint32_t *const p = insn_bytes;

  return (p[0] == 0x24021017 ||
          p[0] == 0x24021061) &&
          p[1] == 0x0000000c;
}

_HIDDEN uintptr_t _jove_emusp_location(void) {
  return (uintptr_t)&__jove_env.xregs[31];
}

_HIDDEN uintptr_t _jove_callstack_location(void) {
  return (uintptr_t)&__jove_callstack;
}

_HIDDEN uintptr_t _jove_callstack_begin_location(void) {
  return (uintptr_t)&__jove_callstack_begin;
}

_HIDDEN void _jove_do_free_callstack(uintptr_t x) {
  _jove_free_callstack(x);
}

_HIDDEN void _jove_do_free_stack_later(uintptr_t x) {
  _jove_free_stack_later(x);
}
