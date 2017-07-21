#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg.h"
#include "qemutcg.h"

static const char *tcg_global_enum_map[] = {
    "tcg::GLOBAL_I32", "tcg::GLOBAL_I64", "tcg::UNDEFINED"};

static void print_tcg_globals_definition(void) {
  for (unsigned i = 0; i < tcg_ctx.nb_globals; ++i) {
    TCGTemp *ts = &tcg_ctx.temps[i];

    //
    // we are interested in TCG global memory regs, not TCG global regs (e.g.
    // env).
    // From target-i386/translate.c:7865, we can see that a TCG global reg has
    // fixed_reg = 1
    //

    printf("{%s, %u, \"%s\"}%s\n",
           ts->fixed_reg ? tcg_global_enum_map[2]
                         : tcg_global_enum_map[ts->type],
           ts->fixed_reg ? 0xdead : (unsigned)ts->mem_offset, ts->name,
           i + 1 == tcg_ctx.nb_globals ? "" : ",");
  }
}

static unsigned num_globals(void) {
  return tcg_ctx.nb_globals;
}

static unsigned num_helpers(void) { return g_hash_table_size(tcg_ctx.helpers); }

static unsigned max_temps(void) { return TCG_MAX_TEMPS; }

static unsigned program_counter_global_index(void) {
  int word_tcg_ty;

  if (sizeof(intptr_t) == 4)
    word_tcg_ty = TCG_TYPE_I32;
  else if (sizeof(intptr_t) == 8)
    word_tcg_ty = TCG_TYPE_I64;
  else
    abort();

  for (unsigned i = 0; i < tcg_ctx.nb_globals; ++i) {
    TCGTemp *ts = &tcg_ctx.temps[i];

    if (!ts->fixed_reg && ts->type == word_tcg_ty &&
        strcmp(ts->name, "pc") == 0)
      return i;
  }

  return 0;
}

static unsigned return_address_global_index(void) {
#if !defined(TARGET_ARM)
  return 0;
#endif

  int word_tcg_ty;

  if (sizeof(intptr_t) == 4)
    word_tcg_ty = TCG_TYPE_I32;
  else if (sizeof(intptr_t) == 8)
    word_tcg_ty = TCG_TYPE_I64;
  else
    abort();

  for (unsigned i = 0; i < tcg_ctx.nb_globals; ++i) {
    TCGTemp *ts = &tcg_ctx.temps[i];

    if (!ts->fixed_reg && ts->type == word_tcg_ty &&
        (strcmp(ts->name, "lr") == 0 || strcmp(ts->name, "r14") == 0))
      return i;
  }

  return 0;
}

static unsigned env_index(void) {
  for (unsigned i = 0; i < tcg_ctx.nb_globals; ++i) {
    TCGTemp *ts = &tcg_ctx.temps[i];

    //
    // we are interested in TCG global memory regs, not TCG global regs (e.g.
    // env).
    // From target-i386/translate.c:7865, we can see that a TCG global reg has
    // fixed_reg = 1
    //

    if (!ts->fixed_reg)
      continue;

    if (strcmp("env", ts->name) == 0)
      return i;
  }

  fprintf(stderr, "could not find env\n");
  abort();
}

static unsigned stack_pointer_global_index(void) {
  int word_tcg_ty;

  if (sizeof(intptr_t) == 4)
    word_tcg_ty = TCG_TYPE_I32;
  else if (sizeof(intptr_t) == 8)
    word_tcg_ty = TCG_TYPE_I64;
  else
    abort();

  const char* name = NULL;
#if defined(TARGET_AARCH64) || defined(TARGET_ARM)
  name = "sp";
#elif defined(TARGET_I386)
  name = "rsp";
#else
#error "TODO"
#endif

  for (unsigned i = 0; i < tcg_ctx.nb_globals; ++i) {
    TCGTemp *ts = &tcg_ctx.temps[i];

    if (!ts->fixed_reg && ts->type == word_tcg_ty &&
        strcmp(ts->name, name) == 0)
      return i;
  }

  return 0;
}

static unsigned cpu_state_program_counter_offset(void) {
#if defined(TARGET_AARCH64)
  return offsetof(CPUARMState, pc);
#elif defined(TARGET_ARM)
  return offsetof(CPUARMState, regs[15]);
#elif defined(TARGET_I386)
  return offsetof(CPUX86State, eip);
#elif defined(TARGET_MIPS)
  return offsetof(CPUMIPSState, active_tc.PC);
#endif
}

#if defined(TARGET_I386)
static unsigned cpu_state_segs_offset() {
  return offsetof(CPUX86State, segs);
}

static unsigned cpu_state_segs_size() {
  return sizeof(((CPUX86State*)0)->segs);
}
#endif

int main(int argc, char **argv) {
  libqemutcg_init();

  if (argc > 1)
    print_tcg_globals_definition();
  else
    printf("#pragma once\n"
           "\n"
           "namespace jove {\n"
           "namespace tcg {\n"
           "constexpr unsigned num_globals = %u;\n"
           "constexpr unsigned num_helpers = %u;\n"
           "constexpr unsigned max_temps = %u;\n"
           "constexpr unsigned program_counter_global_index = %u;\n"
           "constexpr unsigned return_address_global_index = %u;\n"
           "constexpr unsigned stack_pointer_global_index = %u;\n"
           "constexpr unsigned cpu_state_program_counter_offset = %u;\n"
           "constexpr unsigned env_index = %u;\n"
#if defined(TARGET_I386)
           "constexpr unsigned cpu_state_segs_offset = %u;\n"
           "constexpr unsigned cpu_state_segs_size = %u;\n"
#endif
           "}\n"
           "}",
           num_globals(),
           num_helpers(),
           max_temps(),
           program_counter_global_index(),
           return_address_global_index(),
           stack_pointer_global_index(),
           cpu_state_program_counter_offset(),
           env_index()
#if defined(TARGET_I386)
           , cpu_state_segs_offset()
           , cpu_state_segs_size()
#endif
           );

  return 0;
}
