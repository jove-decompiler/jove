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

asm(".text\n"
    _ASM_FN_PROLOGUE(_jove_start) "\n"

    STRINGXV(SETUP_GPX($0)) "\n"

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

    _ASM_FN_EPILOGUE(_jove_start) "\n"
    ".previous");

# undef SETUP_GPX
