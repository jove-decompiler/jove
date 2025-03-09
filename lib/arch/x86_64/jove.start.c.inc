#include "jove.macros.h"

_HIDDEN
_NAKED
void _jove_start(void) {
  asm volatile(
               /* Clear the frame pointer.  The ABI suggests this be done, to
                 mark the outermost frame obviously.  */
               "xorq %%rbp, %%rbp\n"

               "movq %%rsp, %%r9\n"

               /* Align the stack to a 16 byte boundary to follow the ABI.  */
               "andq $~15, %%rsp\n"
               "call _jove_begin\n"
               "hlt\n" /* Crash if somehow `_jove_begin' does return. */

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}
