#include "jove.macros.h"

#ifdef _
#error
#endif

#ifdef JOVE_COFF
#define _ "__"
#else
#define _ "_"
#endif

_HIDDEN
_NAKED
void _jove_start(void) {
  asm volatile(/* Clear the frame pointer.  The ABI suggests this be done, to
                  mark the outermost frame obviously.  */
               "xorl %%ebp, %%ebp\n"

               /* save original sp */
               "movl %%esp, %%ecx\n"

               /* Align the stack to a 16 byte boundary to follow the ABI. */
               "andl $0xfffffff0, %%esp\n"

               /* pass original sp */
               "pushl %%ecx\n"
               "call "_"jove_begin\n"
               "hlt\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}
