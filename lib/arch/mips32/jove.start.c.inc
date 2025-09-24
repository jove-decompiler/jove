#include "jove.macros.h"

asm(".set push\n"
    ".set noreorder\n"
    ".text\n"
    _ASM_FN_PROLOGUE(_jove_start) "\n"

    "bal 0f"           "\n"
    ".word 0x00000000" "\n"

    ".word _jove_start1 - _jove_start" "\n"

"0:\n"
    "lw $a2, ($ra)"    "\n"
    "addu $a2, $ra"    "\n"
    "subu $a2, $a2, 8" "\n"
    "move $t9, $a2"    "\n"
    "bal _jove_start1"    "\n"
    ".word 0x00000000" "\n"

    ".word _jove_begin - _jove_start1" "\n"

    _ASM_FN_EPILOGUE(_jove_start) "\n"
    ".set pop"                    "\n");

asm(".set push\n"
    ".set noreorder\n"
    ".text\n"
    _ASM_FN_PROLOGUE(_jove_start1) "\n"
    ".cpload $t9" "\n"

    "lw $a2, ($ra)"    "\n"
    "addu $a2, $ra"    "\n"
    "addu $a2, $a2, 4" "\n"
    "move $t9, $a2"    "\n"

    /* The return address register is set to zero so that programs
       that search backword through stack frames recognize the last
       stack frame. */
    "move $ra, $0"        "\n"

    "move $a2, $v0"       "\n"
    "move $a3, $sp"       "\n"

    "jalr $t9"            "\n"
    ".word 0x00000000" "\n"

    "break"               "\n"

    _ASM_FN_EPILOGUE(_jove_start1) "\n"
    ".set pop"            "\n");
