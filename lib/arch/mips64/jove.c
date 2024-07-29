#include "cpu_state.h"

#include "jove.common.h"

typedef uint64_t jove_thunk_return_t;

#include "jove.common.c"

_HIDDEN
void _jove_begin(uintptr_t a0,
                 uintptr_t a1,
                 uintptr_t v0,     /* formerly a2 */
                 uintptr_t init_sp /* formerly a3 */) {
  _jove_initialize();

  __jove_env.active_tc.gpr[4] = a0;
  __jove_env.active_tc.gpr[5] = a1;
  __jove_env.active_tc.gpr[2] = v0;
  __jove_env.active_tc.gpr[29] = _jove_begin_setup_emulated_stack(init_sp);

  _jove_call_entry();
}

#define JOVE_THUNK_PROLOGUE                                                    \
  ".set noreorder\n"                                                           \
                                                                               \
  "daddiu $sp,$sp,-64\n"                                                       \
  "sd $ra, 8($sp)\n" /* callee-saved registers */                              \
  "sd $s0, 16($sp)\n"                                                          \
  "sd $s1, 24($sp)\n"

#define JOVE_THUNK_EPILOGUE                                                    \
  "ld $ra, 8($sp)\n" /* callee-saved registers */                              \
  "ld $s0, 16($sp)\n"                                                          \
  "ld $s1, 24($sp)\n"                                                          \
                                                                               \
  "jr $ra\n"                                                                   \
  "daddiu $sp,$sp,64\n"                                                        \
                                                                               \
  ".set reorder\n"

#define JOVE_THUNK_EXTRA_ARGS                                                  \
  "ldc1 $f12, 792($s1)\n" /* floating point arguments */                       \
  "ldc1 $f13, 808($s1)\n"                                                      \
  "ldc1 $f14, 824($s1)\n"

#define JOVE_THUNK_EXTRA_RETS                                                  \
  "sdc1 $f0, 600($s1)\n" /* floating point return values */                    \
  "sdc1 $f1, 616($s1)\n"                                                       \
  "sdc1 $f2, 632($s1)\n"                                                       \
  "sdc1 $f3, 648($s1)\n"

#define JOVE_THUNK_CORE                                                        \
  JOVE_THUNK_EXTRA_ARGS                                                        \
                                                                               \
  "move $s0, $sp\n" /* save sp in $s0 */                                       \
                                                                               \
  /* args: nothing to do */                                                    \
                                                                               \
  "ld $sp, 0($s1)\n"   /* sp=*emuspp */                                        \
  "sd $zero, 0($s1)\n" /* *emuspp=NULL */                                      \
                                                                               \
  "jalr $t9\n" /* call dstpc */                                                \
  "nop\n"                                                                      \
                                                                               \
  "sd $sp, 0($s1)\n" /* store modified emusp */                                \
  "move $sp, $s0\n"  /* restore stack pointer */                               \
                                                                               \
  JOVE_THUNK_EXTRA_RETS                                                        \
                                                                               \
  JOVE_THUNK_EPILOGUE

//
// NOTE: the magic offset is
// offsetof(CPUMIPSState, active_fpu.fpr[0].d) -
// offsetof(CPUMIPSState, active_tc.gpr[29]);
//

jove_thunk_return_t _jove_thunk0(uintptr_t dstpc,  /* $4 */
                                 uintptr_t *emuspp /* $5 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $t9, $4\n" // pc in $t9
               "move $s1, $5\n" // emuspp in $s1

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk1(uintptr_t a0,
                                 uintptr_t dstpc,  /* $5 */
                                 uintptr_t *emuspp /* $6 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $t9, $5\n" // pc in $t9
               "move $s1, $6\n" // emuspp in $s1

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk2(uintptr_t a0,
                                 uintptr_t a1,
                                 uintptr_t dstpc,  /* $6 */
                                 uintptr_t *emuspp /* $7 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $t9, $6\n" // pc in $t9
               "move $s1, $7\n" // emuspp in $s1

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk3(uintptr_t a0,
                                 uintptr_t a1,
                                 uintptr_t a2,
                                 uintptr_t dstpc,  /* $7 */
                                 uintptr_t *emuspp /* $8 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $t9, $7\n" // pc in $t9
               "move $s1, $8\n" // emuspp in $s1

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk4(uintptr_t a0,
                                 uintptr_t a1,
                                 uintptr_t a2,
                                 uintptr_t a3,
                                 uintptr_t dstpc,  /* $8 */
                                 uintptr_t *emuspp /* $9 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $t9, $8\n" // pc in $t9
               "move $s1, $9\n" // emuspp in $s1

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk5(uintptr_t a0,
                                 uintptr_t a1,
                                 uintptr_t a2,
                                 uintptr_t a3,
                                 uintptr_t a4,     /* $8 */
                                 uintptr_t dstpc,  /* $9 */
                                 uintptr_t *emuspp /* $10 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $t9, $9\n"  // pc in $t9
               "move $s1, $10\n" // emuspp in $s1

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk6(uintptr_t a0,
                                 uintptr_t a1,
                                 uintptr_t a2,
                                 uintptr_t a3,
                                 uintptr_t a4,     /* $8 */
                                 uintptr_t a5,     /* $9 */
                                 uintptr_t dstpc,  /* $10 */
                                 uintptr_t *emuspp /* $11 */) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $t9, $10\n" // pc in $t9
               "move $s1, $11\n" // emuspp in $s1

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk7(uintptr_t a0,
                                 uintptr_t a1,
                                 uintptr_t a2,
                                 uintptr_t a3,
                                 uintptr_t a4,     /* $8 */
                                 uintptr_t a5,     /* $9 */
                                 uintptr_t a6,     /* $10 */
                                 uintptr_t dstpc,  /* $11 */
                                 uintptr_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "move $t9, $11\n"   // pc in $t9
               "ld $s1, 64($sp)\n" // emuspp in $s1

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

jove_thunk_return_t _jove_thunk8(uintptr_t a0,
                                 uintptr_t a1,
                                 uintptr_t a2,
                                 uintptr_t a3,
                                 uintptr_t a4, /* $8 */
                                 uintptr_t a5, /* $9 */
                                 uintptr_t a6, /* $10 */
                                 uintptr_t a7, /* $11 */
                                 uintptr_t dstpc,
                                 uintptr_t *emuspp) {
  asm volatile(JOVE_THUNK_PROLOGUE

               "ld $t9, 64($sp)\n" // pc in $t9
               "ld $s1, 72($sp)\n" // emuspp in $s1

               JOVE_THUNK_CORE
               : /* OutputOperands */
               : /* InputOperands */
               : /* Clobbers */);
}

#undef JOVE_THUNK_PROLOGUE
#undef JOVE_THUNK_EPILOGUE

/* when we can rely on t9 being set */
#define SETUP_GP64(gpreg, proc)           \
               .set noreorder;            \
               .cpsetup $25, gpreg, proc; \
               .set reorder

asm(".text\n"
    _ASM_FN_PROLOGUE(_jove_init)         "\n"
    STRINGXV(SETUP_GP64($24,_jove_init)) "\n"

    ".set noreorder\n"

    "daddiu $sp, $sp, -64" "\n" /* allocate stack memory */

    "sd $a0,8($sp)"  "\n" /* save args */
    "sd $a1,16($sp)" "\n"
    "sd $a2,24($sp)" "\n"
    "sd $a3,32($sp)" "\n"

    "sd $ra,40($sp)" "\n" /* save ra */
    "sd $gp,48($sp)" "\n" /* save our gp */
    "sd $24,56($sp)" "\n" /* save original gp */

    /* XXX MAGIC INSTRUCTION BYTES XXX */
    "li $zero, 2345"  "\n" /* nop */
    "li $zero, 345"   "\n" /* nop */
    "li $zero, 45"    "\n" /* nop */
    "li $zero, 5"     "\n" /* nop */
    "li $zero, 54"    "\n" /* nop */
    "li $zero, 543"   "\n" /* nop */
    "li $zero, 5432"  "\n" /* nop */

    "dla $t9, _jove_initialize" "\n"
    "jalr $t9"                  "\n"
    "nop"                       "\n"

    "ld $gp,48($sp)" "\n" /* our gp could have been clobbered */

    "dla $t9, _jove_do_get_init_fn_sect_ptr" "\n"
    "jalr $t9"                               "\n"
    "nop"                                    "\n"

    "beqz $v0, 10f" "\n" /* does DT_INIT function exist? */
    "nop"           "\n"

    "ld $a0,8($sp)"  "\n" /* restore args */
    "ld $a1,16($sp)" "\n"
    "ld $a2,24($sp)" "\n"
    "ld $a3,32($sp)" "\n"

    "move $t9, $v0" "\n"
    "jalr $t9"      "\n" /* call DT_INIT function */
    "nop"           "\n"

"10: ld $ra,40($sp)"      "\n" /* restore ra */
    "ld $gp,56($sp)"      "\n" /* restore original gp */
    "daddiu $sp, $sp, 64" "\n" /* deallocate stack memory */

    "jr $ra" "\n"
    "nop"    "\n"

    ".set reorder\n"
    _ASM_FN_EPILOGUE(_jove_init) "\n"
    ".previous");

//
// XXX hack for glibc 2.32+
//
asm(".text\n"
    _ASM_FN_PROLOGUE(_jove__libc_early_init)         "\n"
    STRINGXV(SETUP_GP64($24,_jove__libc_early_init)) "\n"

    ".set noreorder\n"

    "daddiu $sp, $sp, -64" "\n" /* allocate stack memory */

    "sd $a0,8($sp)"  "\n" /* save args */
    "sd $a1,16($sp)" "\n"
    "sd $a2,24($sp)" "\n"
    "sd $a3,32($sp)" "\n"

    "sd $ra,40($sp)" "\n" /* save ra */
    "sd $gp,48($sp)" "\n" /* save ouur gp */
    "sd $24,56($sp)" "\n" /* save original gp */

    "dla $t9, _jove_do_call_rt_init" "\n"
    "jalr $t9"                       "\n"
    "nop"                            "\n"

    "ld $gp,48($sp)" "\n" /* our gp could have been clobbered */

    "dla $t9, _jove_initialize" "\n"
    "jalr $t9"                  "\n"
    "nop"                       "\n"

    "ld $gp,48($sp)" "\n" /* our gp could have been clobbered */

    "dla $t9, _jove_get_libc_early_init_fn_sect_ptr" "\n"
    "jalr $t9"                                       "\n"
    "nop"                                            "\n"

    "ld $a0,8($sp)"  "\n" /* restore args */
    "ld $a1,16($sp)" "\n"
    "ld $a2,24($sp)" "\n"
    "ld $a3,32($sp)" "\n"

    "move $t9, $v0" "\n"
    "jalr $t9"      "\n" /* call the (recompiled) __libc_early_init */
    "nop"           "\n"

    "ld $ra,40($sp)"      "\n" /* restore ra */
    "ld $gp,56($sp)"      "\n" /* restore original gp */
    "daddiu $sp, $sp, 64" "\n" /* deallocate stack memory */

    "jr $ra" "\n"
    "nop"    "\n"

    ".set reorder\n"
    _ASM_FN_EPILOGUE(_jove__libc_early_init) "\n"
    ".previous");

#undef SETUP_GP64

_HIDDEN void _jove_do_call_rt_init(void) {
  if (_jove_rt_init_clunk)
    _jove_rt_init_clunk();
}

_HIDDEN uintptr_t _jove_do_get_init_fn_sect_ptr(void) {
  return _jove_get_init_fn_sect_ptr();
}

bool _jove_see_through_tramp(const void *ptr, uintptr_t *out) {
  return false;
}
