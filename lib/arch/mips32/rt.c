#define _LARGEFILE64_SOURCE /* for O_LARGEFILE */
#define _GNU_SOURCE         /* for what? TODO */

#include "cpu_state.h"

#include <stddef.h>

/* __thread */ struct CPUMIPSState __jove_env;

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <signal.h>
#include <ucontext.h>

#include "rt.constants.h"
#include "rt.macros.h"

#define JOVE_SYS_ATTR _HIDDEN _UNUSED
#include "jove_sys.h"

#include "rt.util.c"
#include "rt.arch.c"
#include "rt.common.c"

void _jove_inverse_thunk(void) {
  asm volatile("sw $v0,48($sp)" "\n"
               "sw $v1,52($sp)" "\n" /* preserve return registers */

               //
               // free the callstack we allocated in sighandler
               //
               "lw $a0,32($sp)" "\n"
               "lw $a0,0($a0)"  "\n"
               "lw $t9,44($sp)" "\n"
               ".set noreorder" "\n"
               "jalr $t9"       "\n" // _jove_free_callstack(__jove_callstack_begin)
               "nop"            "\n"
               ".set reorder"   "\n"

               //
               // restore __jove_callstack
               //
               "lw $a0,60($sp)" "\n"
               "lw $a1,16($sp)" "\n"
               "sw $a1,0($a0)"  "\n" // __jove_callstack = saved_callstack

               //
               // restore __jove_callstack_begin
               //
               "lw $a0,56($sp)" "\n"
               "lw $a1,20($sp)" "\n"
               "sw $a1,0($a0)"  "\n" // __jove_callstack_begin = saved_callstack_begin

               //
               // mark newstack as to be freed
               //
               "lw $a0,24($sp)" "\n"
               "lw $t9,40($sp)" "\n"
               ".set noreorder" "\n"
               "jalr $t9"       "\n" // _jove_free_stack_later(newstack)
               "nop"            "\n"
               ".set reorder"   "\n"

               //
               // signal handling
               //
               "lw $a0,64($sp)" "\n"
               "lw $a1,72($sp)" "\n"
               "lw $t9,68($sp)" "\n"
               ".set noreorder" "\n"
               "jalr $t9"       "\n" // _jove_handle_signal_delivery(...)
               "nop"            "\n"
               ".set reorder"   "\n"

               "move $a3, $v0"  "\n"

               "lw $v0,48($sp)" "\n"
               "lw $v1,52($sp)" "\n" /* preserve return registers */

               //
               // restore emulated stack pointer
               //
               "lw $a0,28($sp)" "\n" // a0 = &emusp
               //"lw $a3,0($a0)"  "\n" // a3 = emusp

               "lw $a1,12($sp)" "\n" // saved_emusp in $a1
               "sw $a1,0($a0)"  "\n" // restore emusp

               "lw $a2,4($sp)"  "\n" // saved_retaddr in $a2

               ".set noreorder" "\n"
               "jr $a2"         "\n" // pc = saved_retaddr
               "move $sp, $a3"  "\n" // [delay slot] sp = emusp
               ".set reorder"   "\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

bool is_sigreturn_insn_sequence(const void *insn_bytes) {
  const uint32_t *const p = insn_bytes;

  return (p[0] == 0x24021017 ||
          p[0] == 0x24021061) &&
          p[1] == 0x0000000c;
}
