#include "tcg.h"
#include <llvm/Support/raw_ostream.h>
#include <sstream>

static unsigned long __jove_end_pc = 0;

static const void *_jove_g2h(uint64_t Addr, const jove::ELFF *E) {
  llvm::Expected<const uint8_t *> ExpectedPtr = E->toMappedAddr(Addr);
  if (!ExpectedPtr) {
    std::string ErrorBuf;
    {
      llvm::raw_string_ostream OS(ErrorBuf);
      llvm::logAllUnhandledErrors(ExpectedPtr.takeError(), OS, "");
    }

    std::stringstream stream;
    stream << std::hex << Addr;
    std::string AddrHexString(stream.str());
    throw std::runtime_error("_jove_g2h() failed [0x" + AddrHexString +
                             "]: " + ErrorBuf);
  }

  const uint8_t *Ptr = *ExpectedPtr;
  return Ptr;
}

#include "tcg.hpp"
#include "stubs.hpp"

#ifndef g2h
#error "g2h is not defined!"
#endif

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

#include <algorithm>
#include <string>

namespace jove {

static bool do_tcg_optimization = false;

struct tiny_code_generator_private_t {
#if defined(TARGET_X86_64) || defined(TARGET_I386)
  X86CPU _cpu;
#elif defined(TARGET_AARCH64)
  ARMCPU _cpu;
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  MIPSCPU _cpu;
#else
#error "unknown arch"
#endif

  TCGContext _ctx;

  tiny_code_generator_private_t() {
    // zero-initialize CPU
    memset(&_cpu, 0, sizeof(_cpu));

    _cpu.parent_obj.env_ptr = &_cpu.env;

#if defined(TARGET_X86_64)
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
    _cpu.env.features[1] |= CPUID_EXT_XSAVE;
    _cpu.env.features[5] = 563346429;
    _cpu.env.features[6] = 5;
    _cpu.env.user_features[0] = 2;
#elif defined(TARGET_I386)
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
    _cpu.env.features[1] |= CPUID_EXT_XSAVE;
    _cpu.env.user_features[0] = 2;
#elif defined(TARGET_AARCH64)
    _cpu.cp_regs = g_hash_table_new_full(g_int_hash, g_int_equal, g_free,
                                         cpreg_hashtable_data_destroy);

#if 0
    _cpu.env.features = 192517101788915;
    _cpu.env.aarch64 = 1;
#else
    //
    // from aarch64_a57_initfn() in qemu/target/arm/cpu64.c
    //

    _cpu.dtb_compatible = "arm,cortex-a57";

    _cpu.env.features = 0;

    _cpu.env.features |= 1ULL << ARM_FEATURE_V8;
    _cpu.env.features |= 1ULL << ARM_FEATURE_VFP4;
    _cpu.env.features |= 1ULL << ARM_FEATURE_NEON;
    _cpu.env.features |= 1ULL << ARM_FEATURE_GENERIC_TIMER;
    _cpu.env.features |= 1ULL << ARM_FEATURE_AARCH64;
    _cpu.env.features |= 1ULL << ARM_FEATURE_CBAR_RO;
    _cpu.env.features |= 1ULL << ARM_FEATURE_EL2;
    _cpu.env.features |= 1ULL << ARM_FEATURE_EL3;
    _cpu.env.features |= 1ULL << ARM_FEATURE_PMU;

    _cpu.midr = 0x411fd070;
    _cpu.revidr = 0x00000000;
    _cpu.reset_fpsid = 0x41034070;
    _cpu.isar.mvfr0 = 0x10110222;
    _cpu.isar.mvfr1 = 0x12111111;
    _cpu.isar.mvfr2 = 0x00000043;
    _cpu.ctr = 0x8444c004;
    _cpu.reset_sctlr = 0x00c50838;
    _cpu.id_pfr0 = 0x00000131;
    _cpu.id_pfr1 = 0x00011011;
    _cpu.id_dfr0 = 0x03010066;
    _cpu.id_afr0 = 0x00000000;
    _cpu.id_mmfr0 = 0x10101105;
    _cpu.id_mmfr1 = 0x40000000;
    _cpu.id_mmfr2 = 0x01260000;
    _cpu.id_mmfr3 = 0x02102211;
    _cpu.isar.id_isar0 = 0x02101110;
    _cpu.isar.id_isar1 = 0x13112111;
    _cpu.isar.id_isar2 = 0x21232042;
    _cpu.isar.id_isar3 = 0x01112131;
    _cpu.isar.id_isar4 = 0x00011142;
    _cpu.isar.id_isar5 = 0x00011121;
    _cpu.isar.id_isar6 = 0;
    _cpu.isar.id_aa64pfr0 = 0x00002222;
    _cpu.id_aa64dfr0 = 0x10305106;
    _cpu.isar.id_aa64isar0 = 0x00011120;
    _cpu.isar.id_aa64mmfr0 = 0x00001124;
    _cpu.dbgdidr = 0x3516d000;
    _cpu.clidr = 0x0a200023;
    _cpu.ccsidr[0] = 0x701fe00a; /* 32KB L1 dcache */
    _cpu.ccsidr[1] = 0x201fe012; /* 48KB L1 icache */
    _cpu.ccsidr[2] = 0x70ffe07a; /* 2048KB L2 cache */
    _cpu.dcz_blocksize = 4; /* 64 bytes */
    _cpu.gic_num_lrs = 4;
    _cpu.gic_vpribits = 5;
    _cpu.gic_vprebits = 5;

    define_arm_cp_regs(&_cpu, cortex_a72_a57_a53_cp_reginfo);

    _cpu.env.features |= 1ULL << ARM_FEATURE_V7;
    _cpu.env.features |= 1ULL << ARM_FEATURE_VAPA;
    _cpu.env.features |= 1ULL << ARM_FEATURE_THUMB2;
    _cpu.env.features |= 1ULL << ARM_FEATURE_MPIDR;
    _cpu.env.features |= 1ULL << ARM_FEATURE_V6K;
    _cpu.env.features |= 1ULL << ARM_FEATURE_V6;
    _cpu.env.features |= 1ULL << ARM_FEATURE_V5;
    _cpu.env.features |= 1ULL << ARM_FEATURE_V4T;
    _cpu.env.features |= 1ULL << ARM_FEATURE_VBAR;
#endif
#elif defined(TARGET_MIPS64)
    _cpu.env.insn_flags = 511;
    _cpu.env.hflags = 234;
    _cpu.env.CP0_Config1 = -1100926821;
    _cpu.env.CP0_Config2 = -2147483648;
    _cpu.env.CP0_Config3 = 0;
    _cpu.env.CP0_Config4 = 0;
    _cpu.env.CP0_Config5 = 0;
    _cpu.env.PAMask = 68719476735;
    _cpu.env.CP0_LLAddr_shift = 4;
#elif defined(TARGET_MIPS32)
    _cpu.env.insn_flags = 4294967395;
    _cpu.env.hflags = 226;
    _cpu.env.CP0_Config1 = -1642525553;
    _cpu.env.CP0_Config2 = -2147483648;
    _cpu.env.CP0_Config3 = 0;
    _cpu.env.CP0_Config4 = 0;
    _cpu.env.CP0_Config5 = 0;
    _cpu.env.PAMask = 4294967295;
    _cpu.env.CP0_LLAddr_shift = 4;
#else
#error
#endif

    // zero-initialize TCG
    memset(&_ctx, 0, sizeof(_ctx));

    tcg_context_init(&_ctx);
    _ctx.cpu = &_cpu.parent_obj;

#if defined(TARGET_X86_64) || defined(TARGET_I386)
    tcg_x86_init();
#elif defined(TARGET_AARCH64)
    arm_translate_init();

    register_cp_regs_for_features(&_cpu);
    init_cpreg_list(&_cpu);
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    mips_tcg_init();
#else
#error
#endif
  }

  void set_binary(llvm::object::Binary &Bin) {
    assert(llvm::isa<ELFO>(&Bin));
    const ELFF *E = llvm::cast<ELFO>(&Bin)->getELFFile();

    //
    // XXX we hijack a field of CPUArchState to pass the ELFFile handle. this
    // code is paired with definitions of g2h() in tcg.hpp
    //
#if defined(TARGET_X86_64) || defined(TARGET_I386)
    _cpu.env.vm_hsave = (uint64_t)const_cast<void *>((const void *)E);
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    _cpu.env.timer = (QEMUTimer *)const_cast<void *>((const void *)E);
#elif defined(TARGET_AARCH64)
    _cpu.env.nvic = const_cast<void *>((const void *)E);
#else
#error
#endif
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

#if defined(TARGET_X86_64) || \
    defined(TARGET_I386)   || \
    defined(TARGET_MIPS64) || \
    defined(TARGET_MIPS32)
    tb.flags = _cpu.env.hflags;
#elif defined(TARGET_AARCH64)
    tb.flags = R_TBFLAG_ANY_AARCH64_STATE_MASK;
#else
#error
#endif

    tb.jove.T.Addr = pc;
    tb.jove.T.Type = TERMINATOR::UNKNOWN;

    __jove_end_pc = pc_end;

    gen_intermediate_code(&_cpu.parent_obj, &tb, /* max_insn */ 1000000);

    if (do_tcg_optimization)
      tcg_optimize(&_ctx);

    liveness_pass_1(&_ctx);
    if (_ctx.nb_indirects > 0) {
      /* Replace indirect temps with direct temps.  */
      if (liveness_pass_2(&_ctx)) {
        /* If changes were made, re-run liveness.  */
        liveness_pass_1(&_ctx);
      }
    }

#if defined(TARGET_I386) || defined(TARGET_MIPS32)
    struct terminator_info_t &ti = tb.jove.T;

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
#if 0
      if (1 /* opts::Verbose */) {
        std::string text("tcg hack (");
        text.append(std::to_string(__LINE__));
        text.append(") pc=");
        {
          std::stringstream stream;
          stream << std::hex << pc;

          text.append(stream.str());
        }
        text.append(" call.Target=");
        {
          std::stringstream stream;
          stream << std::hex << ti._call.Target;

          text.append(stream.str());
        }
        text.append(" call.NextPC=");
        {
          std::stringstream stream;
          stream << std::hex << ti._call.NextPC;

          text.append(stream.str());
        }
        text.push_back('\n');

        jove::_qemu_log(text.c_str());
      }
#endif

      uintptr_t NextPC = ti._call.NextPC;

      ti.Type = jove::TERMINATOR::UNCONDITIONAL_JUMP;
      ti._unconditional_jump.Target = NextPC;
    }
#endif

    return std::make_pair(tb.size, tb.jove.T);
  }

  void dump_operations(void) {
    tcg_dump_ops(&_ctx, false);
  }
};

tiny_code_generator_t::tiny_code_generator_t()
    : priv(std::make_unique<tiny_code_generator_private_t>()) {}

tiny_code_generator_t::~tiny_code_generator_t() {}

void tiny_code_generator_t::set_binary(llvm::object::Binary &Bin) {
  priv->set_binary(Bin);
}

void tiny_code_generator_t::dump_operations(void) {
  priv->dump_operations();
}

std::pair<unsigned, terminator_info_t>
tiny_code_generator_t::translate(uint64_t pc, uint64_t pc_end) {
  return priv->translate(pc, pc_end);
}

}
