#include "cpu_state.h"

#include <stddef.h>

#define _GNU_SOURCE /* for REG_RIP */
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

#define JOVE_SYS_ATTR _INL _UNUSED

_HIDDEN void _jove_free_stack(uintptr_t);
_HIDDEN void _jove_free_callstack(uintptr_t);
_HIDDEN void _jove_free_stack_later(uintptr_t);
#if 1
_NAKED static void _jove_do_rt_sigreturn(void);
#endif

static uintptr_t _jove_alloc_stack(void);
static uintptr_t _jove_alloc_callstack(void);
static uintptr_t _jove_alloc_large_buffer(void);
static void _jove_free_large_buffer(uintptr_t start);

#include "rt.util.c"
#include "rt.common.c"

#if 0
extern void restore_rt (void) asm ("__restore_rt") __attribute__ ((visibility ("hidden")));
#else
void _jove_do_rt_sigreturn(void) {
  asm volatile("movq $0xf, %rax\n"
               "syscall\n");
}
#endif

void _jove_inverse_thunk(void) {
  asm volatile("pushq $0xdead\n"
               "pushq %%rax\n" /* preserve return registers */
               "pushq %%rdx\n"

               //
               // restore emulated stack pointer
               //
               "call _jove_emusp_location\n" // rax = emuspp

#if 0
               "movq (%%rax), %%rdx\n"   // rdx = emusp
#else /* FIXME */
               "movq 32(%%rsp), %%rdx\n"  // read saved_sp off the stack
               "addq $8, %%rdx\n"         // simulate pop of return addr
#endif
               "movq %%rdx, 16(%%rsp)\n" // replace 0xdead with emusp

               "movq 40(%%rsp), %%rdx\n"  // read saved_emusp off the stack
               "movq %%rdx, (%%rax)\n"    // restore emusp

               //
               // free the callstack we allocated in sighandler
               //
               "call _jove_callstack_begin_location\n"
               "movq (%%rax), %%rdi\n"
               "call _jove_free_callstack\n"

               //
               // restore __jove_callstack
               //
               "call _jove_callstack_location\n" // rax = &__jove_callstack

               "movq 48(%%rsp), %%rdx\n" // edx = saved_callstack
               "movq %%rdx, (%%rax)\n"   // restore callstack

               //
               // restore __jove_callstack_begin
               //
               "call _jove_callstack_begin_location\n" // rax = &__jove_callstack_begin

               "movq 56(%%rsp), %%rdx\n" // edx = saved_callstack_begin
               "movq %%rdx, (%%rax)\n"   // restore callstack_begin

               //
               // mark newstack as to be freed
               //
               "movq 64(%%rsp), %%rdi\n" // rdi = newstack
               "call _jove_free_stack_later\n"

               //
               // signal handling
               //
               "movq 72(%%rsp), %%rdi\n"
               "movq 80(%%rsp), %%rsi\n"
               "call _jove_handle_signal_delivery\n"

               //
               // r11 is the *only* register we can clobber
               //

               "movq 24(%%rsp), %%r11\n"  // read saved_retaddr off the stack

               "popq %%rdx\n"
               "popq %%rax\n"
               "popq %%rsp\n"

               "jmp *%%r11\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

bool is_sigreturn_insn_sequence(const void *insn_bytes) {
  const uint8_t *const p = insn_bytes;

  return p[0] == 0x48 &&
         p[1] == 0xc7 &&
         p[2] == 0xc0 &&
         p[3] == 0x0f &&
         p[4] == 0x00 &&
         p[5] == 0x00 &&
         p[6] == 0x00 &&
         p[7] == 0x0f &&
         p[8] == 0x05;
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

#if 0
asm ( "	nop\n" ".align 16\n" ".LSTART_" "restore_rt" ":\n" "	.type __" "restore_rt" ",@function\n" "__" "restore_rt" ":\n" "	movq $" "15" ", %rax\n" "	syscall\n" ".LEND_" "restore_rt" ":\n" ".section .eh_frame,\"a\",@progbits\n" ".LSTARTFRAME_" "restore_rt" ":\n" "	.long .LENDCIE_" "restore_rt" "-.LSTARTCIE_" "restore_rt" "\n" ".LSTARTCIE_" "restore_rt" ":\n" "	.long 0\n" "	.byte 1\n" "	.string \"zRS\"\n" "	.uleb128 1\n" "	.sleb128 -8\n" "	.uleb128 16\n" "	.uleb128 .LENDAUGMNT_" "restore_rt" "-.LSTARTAUGMNT_" "restore_rt" "\n" ".LSTARTAUGMNT_" "restore_rt" ":\n" "	.byte 0x1b\n" ".LENDAUGMNT_" "restore_rt" ":\n" "	.align " "8" "\n" ".LENDCIE_" "restore_rt" ":\n" "	.long .LENDFDE_" "restore_rt" "-.LSTARTFDE_" "restore_rt" "\n" ".LSTARTFDE_" "restore_rt" ":\n" "	.long .LSTARTFDE_" "restore_rt" "-.LSTARTFRAME_" "restore_rt" "\n" "	.long (.LSTART_" "restore_rt" "-1)-.\n" "	.long .LEND_" "restore_rt" "-(.LSTART_" "restore_rt" "-1)\n" "	.uleb128 0\n" "	.byte 0x0f\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "160" "\n" "	.byte 0x06\n" "2:" "	.byte 0x10\n" "	.uleb128 " "8" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "40" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "9" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "48" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "10" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "56" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "11" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "64" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "12" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "72" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "13" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "80" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "14" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "88" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "15" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "96" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "5" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "104" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "4" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "112" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "6" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "120" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "3" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "128" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "1" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "136" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "0" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "144" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "2" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "152" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "7" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "160" "\n" "2:" "	.byte 0x10\n" "	.uleb128 " "16" "\n" "	.uleb128 2f-1f\n" "1:	.byte 0x77\n" "	.sleb128 " "168" "\n" "2:" "	.align " "8" "\n" ".LENDFDE_" "restore_rt" ":\n" "	.previous\n" );
#endif
