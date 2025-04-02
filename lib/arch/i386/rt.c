#include "rt.common.h"

#include "env.h"

_NAKED static void _jove_do_rt_sigreturn(void);

#include "rt.c.inc"

void _jove_do_rt_sigreturn(void) {
  asm volatile("movl   $0xad,%eax\n"
               "int    $0x80\n");
}

#ifdef _
#error
#endif

#ifdef JOVE_COFF
#define _ "__"
#else
#define _ "_"
#endif

void _jove_inverse_thunk(void) {
  asm volatile("pushl $0xdead\n"
               "pushl %%eax\n" /* preserve return registers */
               "pushl %%edx\n"

               //
               // restore emulated stack pointer
               //
               "call "_"jove_emusp_location\n" // eax = emuspp

               "movl (%%eax), %%edx\n"   // edx = emusp
               "movl %%edx, 8(%%esp)\n" // replace 0xdead with emusp

               "movl 20(%%esp), %%edx\n" // edx = saved_emusp
               "movl %%edx, (%%eax)\n"   // restore emusp

#if 0
               //
               // free the callstack we allocated in sighandler
               //
               "call "_"jove_callstack_begin_location\n"
               "movl (%%eax), %%eax\n"
               "call "_"jove_do_free_callstack\n"
#endif
               //
               // restore __jove_callstack
               //
               "call "_"jove_callstack_location\n" // eax = &__jove_callstack

               "movl 24(%%esp), %%edx\n" // edx = saved_callstack
               "movl $0, (%%edx)\n" /* reset */
               "movl %%edx, (%%eax)\n"   // restore callstack
#if 0
               //
               // restore __jove_callstack_begin
               //
               "call "_"jove_callstack_begin_location\n" // eax = &__jove_callstack_begin

               "movl 28(%%esp), %%edx\n" // edx = saved_callstack_begin
               "movl %%edx, (%%eax)\n"   // restore callstack_begin
#endif

               //
               // mark newstack as to be freed
               //
               "movl 32(%%esp), %%eax\n" // eax = newstack
               "call "_"jove_do_free_stack_later\n"

               //
               // signal handling
               //
               "movl 36(%%esp), %%eax\n"
               "movl 40(%%esp), %%edx\n"
               "call "_"jove_handle_signal_delivery\n"

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
#if 0
_HIDDEN uintptr_t _jove_callstack_begin_location(void) {
  return (uintptr_t)&__jove_callstack_begin;
}
#endif
_REGPARM _HIDDEN void _jove_do_free_stack_later(uintptr_t x) {
  _jove_free_stack_later(x);
}
#if 0
_REGPARM _HIDDEN void _jove_do_free_callstack(uintptr_t x) {
  _jove_free_callstack(x);
}
#endif

int insn_length(const uint8_t *insnp) {
  if (insnp[0] == 0xc7) { /* movl with an immediate to memory */
    // ModR/M byte indicating a memory operand with or without displacement
    uint8_t modrm = insnp[1];
    int length = 1 /* opc */ + 1 /* modrm */ + 4 /* imm */;
    if ((modrm & 0xC0) == 0x40) // disp8(%reg)
      length += 1 /* disp */;
    if ((modrm & 0xC0) == 0x80) // disp32(%reg)
      length += 4 /* disp */;
    if ((modrm & 0x07) == 0x04) { // SIB present
      length += 1 /* SIB */;

      if ((modrm & 0xC0) == 0x00 && (insnp[2] & 0x07) == 0x05) // SIB with disp32
        length += 4 /* disp32 */;
    }
    return length;
  }

  if (insnp[0] == 0x8A) { /* movb from memory or register to register */
    uint8_t modrm = insnp[1];
    int length = 1 /* opc */ + 1 /* modrm */;
    if ((modrm & 0xC0) == 0x40) // disp8(%reg)
      length += 1 /* disp */;
    if ((modrm & 0xC0) == 0x80) // disp32(%reg)
      length += 4 /* disp */;
    if ((modrm & 0x07) == 0x04) { // SIB present
      length += 1 /* SIB */;

      if ((modrm & 0xC0) == 0x00 && (insnp[2] & 0x07) == 0x05) // SIB with disp32
        length += 4 /* disp32 */;
    }

    return length;
  }

  return -1;
}
