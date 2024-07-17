#include "cpu_state.h"
#include <stddef.h>

#define _GNU_SOURCE /* for REG_EIP */
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
#include <ucontext.h>

#include "rt.common.h"

_NAKED static void _jove_do_rt_sigreturn(void);

#include "rt.util.c"
#include "rt.common.c"

void _jove_do_rt_sigreturn(void) {
  asm volatile("movl   $0xad,%eax\n"
               "int    $0x80\n");
}

void _jove_inverse_thunk(void) {
  asm volatile("pushl $0xdead\n"
               "pushl %%eax\n" /* preserve return registers */
               "pushl %%edx\n"

               //
               // restore emulated stack pointer
               //
               "call _jove_emusp_location\n" // eax = emuspp

               "movl (%%eax), %%edx\n"   // edx = emusp
               "movl %%edx, 8(%%esp)\n" // replace 0xdead with emusp

               "movl 20(%%esp), %%edx\n" // edx = saved_emusp
               "movl %%edx, (%%eax)\n"   // restore emusp

               //
               // free the callstack we allocated in sighandler
               //
               "call _jove_callstack_begin_location\n"
               "movl (%%eax), %%eax\n"
               "call _jove_do_free_callstack\n"

               //
               // restore __jove_callstack
               //
               "call _jove_callstack_location\n" // eax = &__jove_callstack

               "movl 24(%%esp), %%edx\n" // edx = saved_callstack
               "movl %%edx, (%%eax)\n"   // restore callstack

               //
               // restore __jove_callstack_begin
               //
               "call _jove_callstack_begin_location\n" // eax = &__jove_callstack_begin

               "movl 28(%%esp), %%edx\n" // edx = saved_callstack_begin
               "movl %%edx, (%%eax)\n"   // restore callstack_begin

               //
               // mark newstack as to be freed
               //
               "movl 32(%%esp), %%eax\n" // eax = newstack
               "call _jove_do_free_stack_later\n"

               //
               // signal handling
               //
               "movl 36(%%esp), %%eax\n"
               "movl 40(%%esp), %%edx\n"
               "call _jove_handle_signal_delivery\n"

               //
               // ecx is the *only* register we can clobber
               //
               "movl 12(%%esp), %%ecx\n" // ecx = saved_retaddr

               "popl %%edx\n"
               "popl %%eax\n"
               "popl %%esp\n"

               "jmp *%%ecx\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

bool is_sigreturn_insn_sequence(const void *insn_bytes) {
  const uint8_t *const p = insn_bytes;

  return p[0] == 0xb8 &&
         p[1] == 0xad &&
         p[2] == 0x00 &&
         p[3] == 0x00 &&
         p[4] == 0x00 &&
         p[5] == 0xcd &&
         p[6] == 0x80;
}

_HIDDEN uintptr_t _jove_emusp_location(void) {
  return (uintptr_t)&__jove_env.regs[R_ESP];
}

_HIDDEN uintptr_t _jove_callstack_location(void) {
  return (uintptr_t)&__jove_callstack;
}

_HIDDEN uintptr_t _jove_callstack_begin_location(void) {
  return (uintptr_t)&__jove_callstack_begin;
}

_REGPARM _HIDDEN void _jove_do_free_stack_later(uintptr_t x) {
  _jove_free_stack_later(x);
}

_REGPARM _HIDDEN void _jove_do_free_callstack(uintptr_t x) {
  _jove_free_callstack(x);
}
