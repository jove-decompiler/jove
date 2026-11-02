#include "qemu.tcg.h"
#include "helper.h"
#include "../qemu/include/jove.h"

#include "tcg.h"
#include "temp.h"

#include <algorithm>
#include <sstream>
#include <string>
#include <llvm/Support/raw_ostream.h>

extern "C" void tcg_dump_ops(TCGContext *s, FILE *f, bool have_prefs);
extern "C" void tcg_register_thread(void);

// using thread-local variables is an easy fix but a lesser fix FIXME
static __THREAD_IF_WE_ARE_MT jove::tiny_code_generator_base_t::context_t *_ctx = nullptr;
static __THREAD_IF_WE_ARE_MT jove::tiny_code_generator_base_t::g2h_t _g2h =
    [](uint64_t) -> void * { return NULL; };

extern "C" void *_jv_g2h(uint64_t Addr) {
  return const_cast<void *>(_g2h(Addr));
}

#define ____ti____(ctx_nm, ti_nm)                                              \
  jove::tiny_code_generator_base_t::context_t *const __pctx = ::_ctx;          \
  assert(__pctx);                                                              \
  jove::tiny_code_generator_base_t::context_t &ctx_nm = *__pctx;               \
  jove::terminator_info_t &ti_nm = ctx_nm.ti

extern "C" void jv_term_is_cond_jump(uint64_t Target, uint64_t NextPC) {
  ____ti____(ctx, ti);

  ti.Type = jove::TERMINATOR::CONDITIONAL_JUMP;
  ti._conditional_jump.Target = Target;
  ti._conditional_jump.NextPC = NextPC;
}

extern "C" void jv_term_is_string_op(void) {
  ____ti____(ctx, ti);

#if defined(TARGET_X86_64) || defined(TARGET_I386)
  ti._conditional_jump.String = true;
#else
  abort();
#endif
}

extern "C" void jv_term_is_uncond_jump(uint64_t Target) {
  ____ti____(ctx, ti);

  ti.Type = jove::TERMINATOR::UNCONDITIONAL_JUMP;
  ti._unconditional_jump.Target = Target;
}

extern "C" void jv_term_is_ind_call(uint64_t NextPC) {
  ____ti____(ctx, ti);

  ti.Type = jove::TERMINATOR::INDIRECT_CALL;
  ti._indirect_call.NextPC = NextPC;
}

extern "C" void jv_term_is_ind_jump(void) {
  ____ti____(ctx, ti);

  ti.Type = jove::TERMINATOR::INDIRECT_JUMP;
}

extern "C" void jv_term_is_return(void) {
  ____ti____(ctx, ti);

  ti.Type = jove::TERMINATOR::RETURN;
}

extern "C" void jv_term_is_call(uint64_t Target, uint64_t NextPC) {
  ____ti____(ctx, ti);

  ti.Type = jove::TERMINATOR::CALL;
  ti._call.Target = Target;
  ti._call.NextPC = NextPC;
}

extern "C" void jv_term_is_none(uint64_t NextPC) {
  ____ti____(ctx, ti);

  ti.Type = jove::TERMINATOR::NONE;
  ti._none.NextPC = NextPC;
  ti.Addr = 0;
}

extern "C" void jv_term_is_unreachable(void) {
  ____ti____(ctx, ti);

  ti.Type = jove::TERMINATOR::UNREACHABLE;
}

extern "C" bool jv_is_term_unknown(void) {
  ____ti____(ctx, ti);

  return ti.Type == jove::TERMINATOR::UNKNOWN;
}

extern "C" uint64_t jv_get_end_pc(void) {
  ____ti____(ctx, ti);

  return ctx.end_pc;
}

extern "C" void jv_term_addr_is(uint64_t Addr) {
  ____ti____(ctx, ti);

  ti.Addr = Addr;
}

extern "C" bool jv_is_term_ind_call(void) {
  ____ti____(ctx, ti);

  return ti.Type == jove::TERMINATOR::INDIRECT_CALL;
}

extern "C" bool jv_is_term_call(void) {
  ____ti____(ctx, ti);

  return ti.Type == jove::TERMINATOR::CALL;
}

extern "C" void jv_ind_call_term_next_pc_is(uint64_t NextPC) {
  ____ti____(ctx, ti);

  ti._indirect_call.NextPC = NextPC;
}

extern "C" void jv_call_term_next_pc_is(uint64_t NextPC) {
  ____ti____(ctx, ti);

  ti._call.NextPC = NextPC;
}

extern "C" void jv_set_end_pc(uint64_t EndPC) {
  ____ti____(ctx, ti);

  ctx.end_pc = EndPC;
}

extern "C" void jv_illegal_op(uint64_t PC) {
  ____ti____(ctx, ti);

  ti.Addr = ~0UL;
  throw jove::illegal_op_exception(PC);
}

#undef ____ti____

#if 0
extern "C" {

struct jove_init_rec {
  int32_t priority;   // same as the i32 field in llvm.global_ctors
  void (*func)(void); // constructor function
  void *data;         // optional associated data (often null)
};

extern struct jove_init_rec __jove_global_ctors_begin[];
extern struct jove_init_rec __jove_global_ctors_end[];
extern struct jove_init_rec __jove_global_dtors_begin[];
extern struct jove_init_rec __jove_global_dtors_end[];

}
#endif

namespace jove {

#if 0
static int by_priority(const void *a, const void *b) {
  const struct jove_init_rec *A = (const struct jove_init_rec *)a;
  const struct jove_init_rec *B = (const struct jove_init_rec *)b;

  if (A->priority < B->priority) return -1;
  if (A->priority > B->priority) return  1;
  return 0;
}

static void run_all_qemu_ctors(void) {
  size_t n = (size_t)(__jove_global_ctors_end - __jove_global_ctors_begin);
  struct jove_init_rec *tmp = (struct jove_init_rec *)
      __builtin_alloca(n * sizeof(struct jove_init_rec));
  for (size_t i = 0; i < n; ++i)
    tmp[i] = __jove_global_ctors_begin[i];
  qsort(tmp, n, sizeof(tmp[0]), by_priority);

  for (size_t i = 0; i < n; ++i) {
    if (tmp[i].func)
      tmp[i].func();
  }
}
#endif

TCGContext *get_tcg_context(void) {
  // FIXME ideally we don't have to rely on thread-local variables.
  static __THREAD_IF_WE_ARE_MT bool _Done = false;

  if (!_Done) {
    _Done = true;
    tcg_register_thread();
  }

  TCGContext *const s = tcg_ctx;
  assert(s);

  return s;
}

int tiny_code_generator_base_t::tcg_index_of_named_global(const char *name) {
  TCGContext *const s = get_tcg_context();
  assert(s);

  for (int i = 0; i < s->nb_globals; i++) {
    if (strcmp(s->temps[i].name, name) == 0)
      return i;
  }

  return -1;
}

const char *tiny_code_generator_base_t::tcg_name_of_global(unsigned glb) {
  TCGContext *const s = get_tcg_context();
  assert(s);

  assert(glb < s->nb_globals);
  return s->temps[glb].name;
}

const void *const *tiny_code_generator_base_t::special_helpers(void) {
  return jv_special_helpers();
}

static const uint8_t starter_bin_bytes[] = {
#include "qemu-starter.inc"
};

static CPUState *get_cpu_state(void) {
  (void)get_tcg_context();

  return thread_cpu;
}

tiny_code_generator_base_t::tiny_code_generator_base_t() {
  static std::mutex mtx;
  static bool _Done = false;

  std::unique_lock<std::mutex> lck(mtx);

  if (!_Done) {
    _Done = true;

    fprintf(stderr, "tiny_code_generator_base_t::tiny_code_generator_base_t\n");

#if 0
    run_all_qemu_ctors();
#endif

    temp_exe the_exe(&starter_bin_bytes[0], sizeof(starter_bin_bytes),
                     "qemu-starter-" TARGET_ARCH_NAME);
    the_exe.store();

    ::jv_init_libqemu(the_exe.path().c_str());
  }
}

void tiny_code_generator_base_t::dump_ops(FILE *out) {
  tcg_dump_ops(get_tcg_context(), out, false);
}

std::pair<unsigned, terminator_info_t>
tiny_code_generator_base_t::do_translate(context_t &ctx, g2h_t g2h,
                                         uint64_t pc,
                                         uint64_t pc_end) {
  TCGContext *const s = get_tcg_context();
  assert(s);

  CPUState *const cs = get_cpu_state();
  assert(cs);
  cs->tcg_cflags |= CF_PARALLEL; /* XXX */

  unsigned tb_size = 0;

  auto &ti = ctx.ti;

  int max_insns = 40;
  TranslationBlock tb;

#ifndef NDEBUG
  //
  // catch bugs
  //
  if (::rand() % 1u == 0u)
    memset(&tb, 0xff, sizeof(tb));
  else
    memset(&tb, 0x00, sizeof(tb));
#endif

  //
  // see tb_gen_code() in qemu/accel/tcg/translate-all.c
  //
  {
    TCGTBCPUState s = cs->cc->tcg_ops->get_tb_cpu_state(cs);

    s.cflags |= CF_PARALLEL;

    tb.cs_base = s.cs_base;
    tb.flags = s.flags;
    tb.cflags = s.flags;
  }

  tb.cflags |= CF_NOIRQ;

  s->cpu = cs;
  s->gen_tb = &tb;
  s->addr_type = sizeof(taddr_t) == 4 ? TCG_TYPE_I32 : TCG_TYPE_I64;
  s->guest_mo = cs->cc->tcg_ops->guest_default_memory_order;

  tb.itree.start = pc & JOVE_PAGE_MASK;
  tb.itree.last = -1;

  ctx.end_pc = pc_end;

  jv_tcg_func_start(s);

  ::_ctx = &ctx;
  ::_g2h = g2h;
  cs->cc->tcg_ops->translate_code(cs, &tb, &max_insns, pc, _jv_g2h(pc));

  tb_size = tb.size;
  assert(tb_size != 0);

#if 0
  tcg_temp_ebb_reset_freed(s);
  tcg_optimize(s);
#endif

#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  if (ti.Type == TERMINATOR::UNCONDITIONAL_JUMP ||
      ti.Type == TERMINATOR::CONDITIONAL_JUMP ||
      ti.Type == TERMINATOR::INDIRECT_CALL ||
      ti.Type == TERMINATOR::INDIRECT_JUMP ||
      ti.Type == TERMINATOR::CALL ||
      ti.Type == TERMINATOR::RETURN) {
    assert(tb_size >= 2 * sizeof(uint32_t));
    tb_size -= sizeof(uint32_t); /* XXX delay slot */
  }
#endif

#if defined(TARGET_I386) || defined(TARGET_MIPS32)
  //
  // On architectures which lack an easy way to reference the program counter
  // when computing an address, you may often see the code having to "twirl"-
  // doing an immediate call to the next instruction and harvesting the return
  // address.
  //
  // It may appear from the outset that the twirl is a call to a real function,
  // but it is not. It is just a way to do position-independent code.
  //
  // Example (mips32):
  //      ...
  // 1d454:       04110001        bal     1d45c
  // 1d458:       00000000        nop
  // 1d45c:       3c1c0018        lui     gp,0x18
  // 1d460:       279c5964        addiu   gp,gp,22884
  // 1d464:       039fe021        addu    gp,gp,ra
  // 1d468:       0020f825        move    ra,at
  //      ...
  //
  // Example (i386):
  //      ...
  // 1055a6:       e8 00 00 00 00          call   1055ab
  // 1055ab:       5b                      pop    %ebx
  //      ...
  //

  if (ti.Type == jove::TERMINATOR::CALL &&
      ti._call.Target == ti._call.NextPC) {
    taddr_t NextPC = ti._call.NextPC;

    ti.Type = jove::TERMINATOR::UNCONDITIONAL_JUMP;
    ti._unconditional_jump.Target = NextPC;
  }
#endif

  return std::make_pair(tb_size, ti);
}

std::pair<tcg_global_set_t, tcg_global_set_t>
tiny_code_generator_base_t::analyze_operation(tcg_helpers_t &helpers, void *op_) {
  TCGOp *op = (TCGOp *)op_;
  const TCGOpcode opc = op->opc;

  tcg_global_set_t iglbs{0}, oglbs{0};

  int nb_oargs, nb_iargs;
  if (opc == INDEX_op_call) {
    nb_oargs = TCGOP_CALLO(op);
    nb_iargs = TCGOP_CALLI(op);

    void *const helper_fn = jv_tcg_helper_func(op);
    if (helper_fn != helpers.Funcs.memset) {

    auto *const pHelperInfo = (TCGHelperInfo *)jv_tcg_helper_info(op);
    assert(pHelperInfo);
    TCGHelperInfo &HelperInfo = *pHelperInfo;

    const tcg_helper_t &hf = helpers.lookup(
        HelperInfo, op, false /* IsCOFF (does not affect analysis result) */);

    iglbs = hf.Analysis.InGlbs;
    oglbs = hf.Analysis.OutGlbs;
    }
  } else {
    nb_iargs = jv_tcgopc_nb_iargs_in_def(opc);
    nb_oargs = jv_tcgopc_nb_oargs_in_def(opc);
  }

  for (int i = 0; i < nb_iargs; ++i) {
    TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);
    if (ts->kind != TEMP_GLOBAL)
      continue;

    unsigned glb_idx = temp_idx(ts);
    if (glb_idx == tcg_env_index)
      continue;

    tcg_global_set_set(iglbs, glb_idx);
  }

  for (int i = 0; i < nb_oargs; ++i) {
    TCGTemp *ts = arg_temp(op->args[i]);
    if (ts->kind != TEMP_GLOBAL)
      continue;

    unsigned glb_idx = temp_idx(ts);
    if (glb_idx == tcg_env_index)
      continue;

    tcg_global_set_set(oglbs, glb_idx);
  }

  return std::make_pair(iglbs, oglbs);
}

void tiny_code_generator_base_t::for_each_operation(std::function<void(void *)> proc) {
  TCGContext *const s = get_tcg_context();

  TCGOp *op;
  QTAILQ_FOREACH(op, &s->ops, link) { proc(op); }
}

}
