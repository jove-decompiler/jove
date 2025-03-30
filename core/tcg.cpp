#include "qemu.tcg.h"
#include "../qemu/include/jove.h"
#include "asm-offsets.h"

#include "tcg.h"
#include "temp.h"

#include <algorithm>
#include <sstream>
#include <string>
#include <llvm/Support/raw_ostream.h>

extern "C" void tcg_dump_ops(TCGContext *s, FILE *f, bool have_prefs);
extern "C" void gen_intermediate_code(CPUState *cpu, TranslationBlock *tb,
                                      int *max_insns, target_ulong pc,
                                      void *host_pc);
extern "C" void tcg_register_thread(void);

static thread_local llvm::object::Binary *jv_Bin;
static thread_local uint64_t jv_end_pc;

static thread_local jove::terminator_info_t jv_ti;

static thread_local unsigned has_register_thread;

extern "C" void *_jv_g2h(uint64_t Addr) {
  if (unlikely(!jv_Bin))
    return NULL;

  const void *const res = jove::B::toMappedAddr(*jv_Bin, Addr);
  if (unlikely(!res))
    throw jove::g2h_exception(Addr);

  return const_cast<void *>(res);
}

extern "C" void jv_term_is_cond_jump(uint64_t Target, uint64_t NextPC) {
  jv_ti.Type = jove::TERMINATOR::CONDITIONAL_JUMP;
  jv_ti._conditional_jump.Target = Target;
  jv_ti._conditional_jump.NextPC = NextPC;
}

extern "C" void jv_term_is_uncond_jump(uint64_t Target) {
  jv_ti.Type = jove::TERMINATOR::UNCONDITIONAL_JUMP;
  jv_ti._unconditional_jump.Target = Target;
}

extern "C" void jv_term_is_ind_call(uint64_t NextPC) {
  jv_ti.Type = jove::TERMINATOR::INDIRECT_CALL;
  jv_ti._indirect_call.NextPC = NextPC;
}

extern "C" void jv_term_is_ind_jump(void) {
  jv_ti.Type = jove::TERMINATOR::INDIRECT_JUMP;
}

extern "C" void jv_term_is_return(void) {
  jv_ti.Type = jove::TERMINATOR::RETURN;
}

extern "C" void jv_term_is_call(uint64_t Target, uint64_t NextPC) {
  jv_ti.Type = jove::TERMINATOR::CALL;
  jv_ti._call.Target = Target;
  jv_ti._call.NextPC = NextPC;
}

extern "C" void jv_term_is_none(uint64_t NextPC) {
  jv_ti.Type = jove::TERMINATOR::NONE;
  jv_ti._none.NextPC = NextPC;
  jv_ti.Addr = 0;
}

extern "C" void jv_term_is_unreachable(void) {
  jv_ti.Type = jove::TERMINATOR::UNREACHABLE;
}

extern "C" bool jv_is_term_unknown(void) {
  return jv_ti.Type == jove::TERMINATOR::UNKNOWN;
}

extern "C" uint64_t jv_get_end_pc(void) {
  return jv_end_pc;
}

extern "C" void jv_term_addr_is(uint64_t Addr) {
  jv_ti.Addr = Addr;
}

extern "C" bool jv_is_term_ind_call(void) {
  return jv_ti.Type == jove::TERMINATOR::INDIRECT_CALL;
}

extern "C" bool jv_is_term_call(void) {
  return jv_ti.Type == jove::TERMINATOR::CALL;
}

extern "C" void jv_ind_call_term_next_pc_is(uint64_t NextPC) {
  jv_ti._indirect_call.NextPC = NextPC;
}

extern "C" void jv_call_term_next_pc_is(uint64_t NextPC) {
  jv_ti._call.NextPC = NextPC;
}

extern "C" void jv_set_end_pc(uint64_t EndPC) {
  jv_end_pc = EndPC;
}

extern "C" void jv_illegal_op(uint64_t PC) {
  jv_ti.Addr = ~0UL;
  throw jove::illegal_op_exception(PC);
}


extern CPUState *jv_cpu;

namespace jove {

static const char *cstr_of_tcg_type(TCGType x) {
#define ___CASE(text)                                                          \
  if (x == BOOST_PP_CAT(TCG_TYPE_, text))                                      \
    return BOOST_PP_STRINGIZE(text);

  ___CASE(I32);
  ___CASE(I64);
  ___CASE(V64);
  ___CASE(V128);
  ___CASE(V256);

#undef ___CASE

  abort();
}

int tiny_code_generator_t::tcg_index_of_named_global(const char *name) {
  assert(tcg_ctx);

  for (int i = 0; i < tcg_ctx->nb_globals; i++) {
    if (strcmp(tcg_ctx->temps[i].name, name) == 0)
      return i;
  }

  return -1;
}

static const uint8_t starter_bin_bytes[] = {
#include "qemu-starter.inc"
};

tiny_code_generator_t::tiny_code_generator_t() {
  temp_executable temp_exe(&starter_bin_bytes[0],
                           sizeof(starter_bin_bytes),
                           "qemu-starter-" TARGET_ARCH_NAME);
  temp_exe.store();

  jv_init_libqemu(temp_exe.path().c_str());
}

tiny_code_generator_t::~tiny_code_generator_t() {}

void tiny_code_generator_t::set_binary(llvm::object::Binary &Bin) {
  ::jv_Bin = &Bin;
}

void tiny_code_generator_t::dump_operations(void) {
  fflush(stdout);
  tcg_dump_ops(tcg_ctx, stdout, false);
  fflush(stdout);
}

std::pair<unsigned, terminator_info_t>
tiny_code_generator_t::translate(uint64_t pc, uint64_t pc_end) {
  rassert(jv_cpu);

  if (!has_register_thread) {
    has_register_thread = 1;
    tcg_register_thread();
  }

  TCGContext *s = tcg_ctx;
  assert(s);

  unsigned tb_size = 0;

  jv_ti.Type = TERMINATOR::UNKNOWN;
  jv_ti.Addr = ~0UL;

  int max_insns = 64;
  TranslationBlock tb = {0};
  tb.flags = jv_hflags_of_cpu_env(jv_cpu);
  tb.cflags = jv_cpu->tcg_cflags | CF_NOIRQ | 0u /* CF_PCREL */;

#if 0
  assert(!(tb.cflags & CF_PCREL));
#endif

  //printf("tb.flags=0x%x\n", tb.flags);
  //printf("tb.cflags=0x%x\n", tb.cflags);

  s->gen_tb = &tb;
  s->addr_type = TCG_TARGET_REG_BITS == 32 ? TCG_TYPE_I32 : TCG_TYPE_I64;

  jv_init_tcg_ctx(s);

#if 0
  tb.flags = jv_cpu->hflags |
      (jv_cpu->eflags & (IOPL_MASK | TF_MASK | RF_MASK | VM_MASK | AC_MASK));
#endif

  jv_end_pc = pc_end;

  jv_tcg_func_start(s);

  CPUState *cs = jv_cpu;
  tcg_ctx->cpu = cs;
  cs->cc->tcg_ops->translate_code(cs, &tb, &max_insns, pc, _jv_g2h(pc));

  tb_size = tb.size;
  assert(tb_size != 0);

#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  if (jv_ti.Type == TERMINATOR::UNCONDITIONAL_JUMP ||
      jv_ti.Type == TERMINATOR::CONDITIONAL_JUMP ||
      jv_ti.Type == TERMINATOR::INDIRECT_CALL ||
      jv_ti.Type == TERMINATOR::INDIRECT_JUMP ||
      jv_ti.Type == TERMINATOR::CALL ||
      jv_ti.Type == TERMINATOR::RETURN) {
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

  if (jv_ti.Type == jove::TERMINATOR::CALL &&
      jv_ti._call.Target == jv_ti._call.NextPC) {
    taddr_t NextPC = jv_ti._call.NextPC;

    jv_ti.Type = jove::TERMINATOR::UNCONDITIONAL_JUMP;
    jv_ti._unconditional_jump.Target = NextPC;
  }
#endif

  return std::make_pair(tb_size, jv_ti);
}

}
