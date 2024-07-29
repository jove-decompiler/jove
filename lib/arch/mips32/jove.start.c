#include "jove.macros.h"

_HIDDEN
_NAKED
void _jove_start(void) {
  asm volatile(".set noreorder"      "\n"
               ".cpload $t9"         "\n" /* set up gp */

               /* The return address register is set to zero so that programs
                  that search backword through stack frames recognize the last
                  stack frame. */
               "move $ra, $0"        "\n"

               "move $a2, $v0"       "\n"
               "move $a3, $sp"       "\n"

               "la $t9, _jove_begin" "\n" /* needs gp set up */
               "jalr $t9"            "\n"
               "nop"                 "\n"

               "break"               "\n"
               ".set reorder"        "\n"

               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}
