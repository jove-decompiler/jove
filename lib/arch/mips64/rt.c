#include "cpu_state.h"

#include "rt.common.h"
#include "rt.common.c"

void _jove_inverse_thunk(void) {
  asm volatile("sd $v0,96($sp)"  "\n"
               "sd $v1,104($sp)" "\n" /* preserve return registers */

               //
               // free the callstack we allocated in sighandler
               //
               "ld $a0,64($sp)" "\n"
               "ld $a0,0($a0)"  "\n"
               "ld $t9,88($sp)" "\n"
               ".set noreorder" "\n"
               "jalr $t9"       "\n" // _jove_free_callstack(__jove_callstack_begin)
               "nop"            "\n"
               ".set reorder"   "\n"

               //
               // restore __jove_callstack
               //
               "ld $a0,120($sp)" "\n"
               "ld $a1,32($sp)"  "\n"
               "sd $a1,0($a0)"   "\n" // __jove_callstack = saved_callstack

               //
               // restore __jove_callstack_begin
               //
               "ld $a0,112($sp)" "\n"
               "ld $a1,40($sp)"  "\n"
               "sd $a1,0($a0)"   "\n" // __jove_callstack_begin = saved_callstack_begin

               //
               // mark newstack as to be freed
               //
               "ld $a0,48($sp)" "\n"
               "ld $t9,80($sp)" "\n"
               ".set noreorder" "\n"
               "jalr $t9"       "\n" // _jove_free_stack_later(newstack)
               "nop"            "\n"
               ".set reorder"   "\n"

               //
               // signal handling
               //
               "ld $a0,128($sp)" "\n"
               "ld $a1,144($sp)" "\n"
               "ld $t9,136($sp)" "\n"
               ".set noreorder"  "\n"
               "jalr $t9"        "\n" // _jove_handle_signal_delivery(...)
               "nop"             "\n"
               ".set reorder"    "\n"

               "move $a3, $v0"   "\n"

               "ld $v0,96($sp)"  "\n"
               "ld $v1,104($sp)" "\n" /* preserve return registers */

               //
               // restore emulated stack pointer
               //
               "ld $a0,56($sp)" "\n" // a0 = &emusp
               //"ld $a3,0($a0)"  "\n" // a3 = emusp

               "ld $a1,24($sp)" "\n" // saved_emusp in $a1
               "sd $a1,0($a0)"  "\n" // restore emusp

               "ld $a2,8($sp)"  "\n" // saved_retaddr in $a2

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
