#include "jove.macros.h"

# define SETUP_GPX(r)					\
		.set noreorder;				\
		move r, $31;	 /* Save old ra.  */	\
		bal 10f; /* Find addr of cpload.  */	\
		nop;					\
10:							\
		.cpload $31;				\
		move $31, r;				\
		.set reorder

asm(".set push\n"
    ".set noreorder\n"
    ".text\n"
    _ASM_FN_PROLOGUE(_jove_start) "\n"

#if 0
    STRINGXV(SETUP_GPX($0)) "\n"
#else
    "bal 10f" "\n"
    "nop"     "\n"
    ".word _jove_begin - _jove_start" "\n"
"10:\n"

    "lw $a2, 0($ra)"       "\n"
    "addu $a2, $ra"        "\n"
    "subu $a2, $a2, 8"     "\n"
    "move $t9, $a2"        "\n"
#endif

    /* The return address register is set to zero so that programs
       that search backword through stack frames recognize the last
       stack frame. */
    "move $ra, $0"        "\n"

    "move $a2, $v0"       "\n"
    "move $a3, $sp"       "\n"

#if 0
    "la $t9, _jove_begin" "\n" /* needs gp set up */
#endif

    "jalr $t9"            "\n"
    "nop"                 "\n"

    "break"               "\n"

    _ASM_FN_EPILOGUE(_jove_start) "\n"
    ".set pop"            "\n");

# undef SETUP_GPX
