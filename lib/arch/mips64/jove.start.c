#include "jove.macros.h"

# define SETUP_GPX64(cp_reg, ra_save)			\
		move ra_save, $31; /* Save old ra.  */	\
		.set noreorder;				\
		bal 10f; /* Find addr of .cpsetup.  */	\
		nop;					\
10:							\
		.set reorder;				\
		.cpsetup $31, cp_reg, 10b;		\
		move $31, ra_save

asm(".text\n"
    _ASM_FN_PROLOGUE(_jove_start) "\n"

    STRINGXV(SETUP_GPX64($0,$0))  "\n"

    /* The return address register is set to zero so that programs
       that search backword through stack frames recognize the last
       stack frame. */
    "move $ra, $0"                "\n"

    "move $a2, $v0"               "\n"
    "move $a3, $sp"               "\n"

    "dla $t9, _jove_begin"        "\n"
    "jalr $t9"                    "\n"
    "nop"                         "\n"

    "break"                       "\n"

    _ASM_FN_EPILOGUE(_jove_start) "\n"
    ".previous");
