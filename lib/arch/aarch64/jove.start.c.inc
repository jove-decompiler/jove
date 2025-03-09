#include "jove.macros.h"

_HIDDEN
_NAKED
void _jove_start(void) {
  asm volatile(/* Create an initial frame with 0 LR and FP */
               "mov x29, #0\n"
               "mov x30, #0\n"

               "mov x7, sp\n"
               "b _jove_begin\n");
}
