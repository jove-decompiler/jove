#include "jove/jove.h"

static unsigned long guest_base_addr;
#define g2h(x) ((void *)((((unsigned long)(target_ulong)(x)) - guest_base_addr) + guest_base))

#include "tcg.hpp"
#include "stubs.hpp"

//
// global stubs
//
TraceEvent _TRACE_GUEST_MEM_BEFORE_EXEC_EVENT = {0};
TraceEvent _TRACE_GUEST_MEM_BEFORE_TRANS_EVENT = {0};
uint16_t _TRACE_OBJECT_CLASS_DYNAMIC_CAST_ASSERT_DSTATE;
int singlestep;
int qemu_loglevel;
int trace_events_enabled_count;
unsigned long guest_base;
FILE *qemu_logfile = stdout;
bool qemu_log_in_addr_range(uint64_t addr) { return false; }
const char *lookup_symbol(target_ulong orig_addr) { return nullptr; }
void target_disas(FILE *out, CPUState *cpu, target_ulong code,
                  target_ulong size) {}
void cpu_abort(CPUState *cpu, const char *fmt, ...) {
  abort();
}

namespace jove {
static void _qemu_log(const char *);
}

int qemu_log(const char *fmt, ...) {
  int size;
  va_list ap;

  /* Determine required size */

  va_start(ap, fmt);
  size = vsnprintf(nullptr, 0, fmt, ap);
  va_end(ap);

  if (size < 0)
    return 0;

  size++; /* For '\0' */
  char *p = (char *)malloc(size);
  if (!p)
    return 0;

  va_start(ap, fmt);
  size = vsnprintf(p, size, fmt, ap);
  va_end(ap);

  if (size < 0) {
    free(p);
    return 0;
  }

  jove::_qemu_log(p);
  free(p);

  return size;
}

namespace jove {

struct tiny_code_generator_t {
#if defined(__x86_64__) || defined(__i386__)
  X86CPU _cpu;
#elif defined(__aarch64__)
  ARMCPU _cpu;
#endif

  TCGContext _ctx;

  tiny_code_generator_t() {
    // zero-initialize CPU
    memset(&_cpu, 0, sizeof(_cpu));

    _cpu.parent_obj.env_ptr = &_cpu.env;

#if defined(__x86_64__)
    _cpu.env.eflags = 514;
    _cpu.env.hflags = 0x0040c0b3;
    _cpu.env.hflags2 = 1;
    _cpu.env.a20_mask = -1;
    _cpu.env.cr[0] = 0x80010001;
    _cpu.env.cr[4] = 0x00000220;
    _cpu.env.mxcsr = 0x00001f80;
    _cpu.env.xcr0 = 3;
    _cpu.env.msr_ia32_misc_enable = 1;
    _cpu.env.pat = 0x0007040600070406ULL;
    _cpu.env.smbase = 0x30000;
    _cpu.env.features[0] = 126614525;
    _cpu.env.features[1] = 2147491841;
    _cpu.env.features[5] = 563346429;
    _cpu.env.features[6] = 5;
    _cpu.env.user_features[0] = 2;
#elif defined(__i386__)
    _cpu.env.eflags = 514;
    _cpu.env.hflags = 0x004000b3;
    _cpu.env.hflags2 = 1;
    _cpu.env.a20_mask = -1;
    _cpu.env.cr[0] = 0x80010001;
    _cpu.env.cr[4] = 0x00000200;
    _cpu.env.mxcsr = 0x00001f80;
    _cpu.env.xcr0 = 3;
    _cpu.env.msr_ia32_misc_enable = 1;
    _cpu.env.pat = 0x0007040600070406ULL;
    _cpu.env.smbase = 0x30000;
    _cpu.env.features[0] = 125938685;
    _cpu.env.features[1] = 2147483649;
    _cpu.env.user_features[0] = 2;
#elif defined(__aarch64__)
    _cpu.env.aarch64 = 1;
    _cpu.env.features = 192517101788915;
#endif

    // zero-initialize TCG
    memset(&_ctx, 0, sizeof(_ctx));

    tcg_context_init(&_ctx);
    _ctx.cpu = &_cpu.parent_obj;

#if defined(__x86_64__) || defined(__i386__)
    tcg_x86_init();
#elif defined(__aarch64__)
    arm_translate_init();
#endif
  }

  void set_section(target_ulong base, const void *contents) {
    guest_base_addr = base;
    guest_base = reinterpret_cast<unsigned long>(contents);
  }

  std::pair<unsigned, terminator_info_t> translate(target_ulong pc,
                                                   target_ulong pc_end = 0) {
    tcg_func_start(&_ctx);

    struct TranslationBlock tb;

    // zero-initialize TranslationBlock
    memset(&tb, 0, sizeof(tb));

    tcg_ctx = &_ctx;

    uint32_t cflags = CF_PARALLEL;
    tcg_ctx->tb_cflags = cflags;
    tb.cflags          = cflags;

    tb.pc = pc;
#if defined(__x86_64__) || defined(__i386__)
    tb.flags = _cpu.env.hflags;
#elif defined(__aarch64__)
    tb.flags = ARM_TBFLAG_AARCH64_STATE_MASK;
#endif
    tb.jove.T.Addr = pc;
    tb.jove.T.Type = TERMINATOR::UNKNOWN;

    __jove_end_pc = pc_end;
    gen_intermediate_code(&_cpu.parent_obj, &tb);

#if 0
    tcg_optimize(&_ctx);
#endif

    liveness_pass_1(&_ctx);
    if (_ctx.nb_indirects > 0) {
      /* Replace indirect temps with direct temps.  */
      if (liveness_pass_2(&_ctx)) {
        /* If changes were made, re-run liveness.  */
        liveness_pass_1(&_ctx);
      }
    }

#if defined(__i386__)
    struct terminator_info_t &ti = tb.jove.T;

    /* quirk */
    if (ti.Type == jove::TERMINATOR::CALL &&
        ti._call.Target == ti._call.NextPC) {
      uintptr_t NextPC = ti._call.NextPC;

      ti.Type = jove::TERMINATOR::UNCONDITIONAL_JUMP;
      ti._unconditional_jump.Target = NextPC;
    }
#endif

    return std::make_pair(tb.size, tb.jove.T);
  }

  void dump_operations(void) {
    tcg_dump_ops(&_ctx);
  }
};

}
