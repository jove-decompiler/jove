#ifndef JOVE_SINGLESTEP_OPCODE
#error
#endif

#define JOVE_PARAM_DECL(r, data, i, elem)                                      \
  BOOST_PP_COMMA_IF(i)                                                         \
  BOOST_PP_TUPLE_ELEM(2, 0, elem) /* Type */                                   \
  /* space */                                                                  \
  BOOST_PP_TUPLE_ELEM(2, 1, elem) /* Name */

#define JOVE_SINGLESTEP_PARAMS_DECL                                            \
  BOOST_PP_SEQ_FOR_EACH_I(JOVE_PARAM_DECL, _, BOOST_PP_CAT(BOOST_PP_CAT(JOVE_SINGLESTEP_,JOVE_SINGLESTEP_OPCODE),_PARAMETERS))

template <unsigned Opcode, JOVE_SINGLESTEP_PARAMS_DECL>
__attribute__((flatten))
#if !defined(__x86_64__) && defined(__i386__)
__attribute__((regparm(3)))
#endif
static uintptr_t BOOST_PP_CAT(BOOST_PP_CAT(single_step_,JOVE_SINGLESTEP_OPCODE),_proc)(
    ptrace::tracee_state_t &tracee_state, trapped_t &trapped, pid_t child
#if defined(__mips64) || defined(__mips__)
  , uintptr_t ExecutableRegionAddress
#endif
) noexcept {
  auto &gpr = tracee_state;

  const uintptr_t savedpc = ptrace::pc_of_tracee_state(tracee_state);
  RegValue_t nextpc = savedpc + trapped.IL;
#if defined(__mips64) || defined(__mips__)
  RegValue_t nextnextpc = nextpc + 4;
#endif

#if defined(__i386__)
  struct {
    long ss;
    long cs;
    long ds;
    long es;
    long fs;
    long gs;
  } _hack; /* purely so we can take a reference to the segment fields */
#endif

  auto LoadAddr = [&](uintptr_t addr) -> uintptr_t {
    return ptrace::peekdata<false>(child, addr);
  };

  auto RegValue = [&](unsigned llreg) -> RegValue_t & {
    switch (llreg) {
#if defined(__x86_64__)
    case llvm::X86::RAX:
      return gpr.rax;
    case llvm::X86::RBP:
      return gpr.rbp;
    case llvm::X86::RBX:
      return gpr.rbx;
    case llvm::X86::RCX:
      return gpr.rcx;
    case llvm::X86::RDI:
      return gpr.rdi;
    case llvm::X86::RDX:
      return gpr.rdx;
    case llvm::X86::RIP:
      return nextpc;
    case llvm::X86::RSI:
      return gpr.rsi;
    case llvm::X86::RSP:
      return gpr.rsp;

#define __REG_CASE(n, i, data)                                                 \
  case BOOST_PP_CAT(llvm::X86::R, i):                                          \
    return BOOST_PP_CAT(gpr.r, i);

BOOST_PP_REPEAT_FROM_TO(8, 16, __REG_CASE, void)

#undef __REG_CASE

#elif defined(__i386__)

    case llvm::X86::EAX:
      return gpr.eax;
    case llvm::X86::EBP:
      return gpr.ebp;
    case llvm::X86::EBX:
      return gpr.ebx;
    case llvm::X86::ECX:
      return gpr.ecx;
    case llvm::X86::EDI:
      return gpr.edi;
    case llvm::X86::EDX:
      return gpr.edx;
    case llvm::X86::EIP:
      return nextpc;
    case llvm::X86::ESI:
      return gpr.esi;
    case llvm::X86::ESP:
      return gpr.esp;

    //
    // for segment registers, return the base address of the segment descriptor
    // which they reference (bits 15-3)
    //
    case llvm::X86::SS:
      _hack.ss = ptrace::segment_address_of_selector(child, gpr.xss);
      return _hack.ss;

    case llvm::X86::CS:
      _hack.cs = ptrace::segment_address_of_selector(child, gpr.xcs);
      return _hack.cs;

    case llvm::X86::DS:
      _hack.ds = ptrace::segment_address_of_selector(child, gpr.xds);
      return _hack.ds;

    case llvm::X86::ES:
      _hack.es = ptrace::segment_address_of_selector(child, gpr.xes);
      return _hack.es;

    case llvm::X86::FS:
      _hack.fs = ptrace::segment_address_of_selector(child, gpr.xfs);
      return _hack.fs;

    case llvm::X86::GS:
      _hack.gs = ptrace::segment_address_of_selector(child, gpr.xgs);
      return _hack.gs;

#elif defined(__aarch64__)

#define __REG_CASE(n, i, data)                                                 \
  case BOOST_PP_CAT(llvm::AArch64::X, i):                                      \
    return gpr.regs[i];

BOOST_PP_REPEAT(29, __REG_CASE, void)

#undef __REG_CASE

    case llvm::AArch64::FP:
      return gpr.regs[29];
    case llvm::AArch64::LR:
      return gpr.regs[30];
    case llvm::AArch64::SP:
      return gpr.sp;

#elif defined(__mips64) || defined(__mips__)

    case llvm::Mips::ZERO: assert(gpr.regs[0] == 0); return gpr.regs[0];
    case llvm::Mips::AT: return gpr.regs[1];
    case llvm::Mips::V0: return gpr.regs[2];
    case llvm::Mips::V1: return gpr.regs[3];
    case llvm::Mips::A0: return gpr.regs[4];
    case llvm::Mips::A1: return gpr.regs[5];
    case llvm::Mips::A2: return gpr.regs[6];
    case llvm::Mips::A3: return gpr.regs[7];
    case llvm::Mips::T0: return gpr.regs[8];
    case llvm::Mips::T1: return gpr.regs[9];
    case llvm::Mips::T2: return gpr.regs[10];
    case llvm::Mips::T3: return gpr.regs[11];
    case llvm::Mips::T4: return gpr.regs[12];
    case llvm::Mips::T5: return gpr.regs[13];
    case llvm::Mips::T6: return gpr.regs[14];
    case llvm::Mips::T7: return gpr.regs[15];
    case llvm::Mips::S0: return gpr.regs[16];
    case llvm::Mips::S1: return gpr.regs[17];
    case llvm::Mips::S2: return gpr.regs[18];
    case llvm::Mips::S3: return gpr.regs[19];
    case llvm::Mips::S4: return gpr.regs[20];
    case llvm::Mips::S5: return gpr.regs[21];
    case llvm::Mips::S6: return gpr.regs[22];
    case llvm::Mips::S7: return gpr.regs[23];
    case llvm::Mips::T8: return gpr.regs[24];
    case llvm::Mips::T9: return gpr.regs[25];


    case llvm::Mips::GP: return gpr.regs[28];
    case llvm::Mips::SP: return gpr.regs[29];
    case llvm::Mips::FP: return gpr.regs[30];
    case llvm::Mips::RA: return gpr.regs[31];

#else
#error
#endif

    default:
      __builtin_trap();
      __builtin_unreachable();
    }
  };

#if defined(__mips64) || defined(__mips__)
  auto emulate_delay_slot = [&](const unsigned r) -> uintptr_t {
    if constexpr (DelaySlotOpcode == llvm::Mips::INSTRUCTION_LIST_END) {
      unsigned idx = code_cave_idx_of_reg(r);
      uintptr_t jumpr_insn_addr = ExecutableRegionAddress +
                                  idx * (2 * sizeof(ptrace::word));
      uintptr_t delay_slot_addr = jumpr_insn_addr + 4;

      uint32_t insns[2] = {
        encoding_of_jump_to_reg(reg_of_idx(idx)),
        trapped.DelaySlotInsn
      };

      static_assert(sizeof(ptrace::word) == 8 ||
                    sizeof(ptrace::word) == 4);

      if (sizeof(ptrace::word) == 8) {
        ptrace::word the_poke;
        __builtin_memcpy_inline(&the_poke, &insns[0], sizeof(the_poke));
        ptrace::pokedata(child, jumpr_insn_addr, the_poke);
      } else {
#if 0
        ptrace::word the_poke1;
        __builtin_memcpy_inline(&the_poke1, &insns[0], sizeof(the_poke1));
        ptrace::pokedata(child, jumpr_insn_addr, the_poke1);
#endif /* unnecessary */

        ptrace::word the_poke2;
        __builtin_memcpy_inline(&the_poke2, &insns[1], sizeof(the_poke2));
        ptrace::pokedata(child, delay_slot_addr, the_poke2);
      }

      return jumpr_insn_addr;
    }

    __compiletime_unreachable();
  };

#else

  auto emulate = [&](void) -> uintptr_t {
#if defined(__x86_64__)
    if constexpr (Opcode == llvm::X86::JMP64r ||
                  Opcode == llvm::X86::CALL64r) {
      return RegValue(Reg0);
    }

    if constexpr (Opcode == llvm::X86::JMP64m ||
                  Opcode == llvm::X86::CALL64m) {
      unsigned x_r = Reg0;
      unsigned y_r = Reg2;

      long x = x_r == llvm::X86::NoRegister ? 0L : RegValue(x_r);
      long A = 1 << trapped.Scale;
      long y = y_r == llvm::X86::NoRegister ? 0L : RegValue(y_r);
      long B = trapped.Disp;

      return LoadAddr(x + A * y + B);
    }

    if constexpr (Opcode == llvm::X86::RET64) {
      uintptr_t res = LoadAddr(RegValue(RetReg0));
      gpr.rsp += (8 + trapped.Disp);
      return res;
    }

#elif defined(__i386__)

    if constexpr (Opcode == llvm::X86::JMP32r ||
                  Opcode == llvm::X86::CALL32r) {
      return RegValue(Reg0);
    }

    if constexpr (Opcode == llvm::X86::JMP32m ||
                  Opcode == llvm::X86::CALL32m) {
      long B = trapped.Disp;

      if (Reg4 == llvm::X86::NoRegister) {
        unsigned x_r = Reg0;
        unsigned y_r = Reg2;

        long x = x_r == llvm::X86::NoRegister ? 0L : RegValue(x_r);
        long A = 1 << trapped.Scale;
        long y = y_r == llvm::X86::NoRegister ? 0L : RegValue(y_r);

        return LoadAddr(x + A * y + B);
      } else {
        /* e.g. call dword ptr gs:[16] */
        return LoadAddr(RegValue(Reg4) + B);
      }
    }

    if constexpr (Opcode == llvm::X86::RET32) {
      uintptr_t res = LoadAddr(RegValue(RetReg0));
      gpr.esp += 4;
      return res;
    }

    if constexpr (Opcode == llvm::X86::RETI32) {
      uintptr_t res = LoadAddr(RegValue(RetReg0));
      gpr.esp += (4 + trapped.Disp);
      return res;
    }

#elif defined(__aarch64__)

    if constexpr (Opcode == llvm::AArch64::BR ||
                  Opcode == llvm::AArch64::BLR)
      return RegValue(Reg0);

    if constexpr (Opcode == llvm::AArch64::RET)
      return RegValue(RetReg0 == llvm::AArch64::NoRegister ? llvm::AArch64::LR
                                                           : RetReg0);

#else
#error
#endif

    __compiletime_unreachable();
  };
#endif

#if 1
  auto emulate_call = [&](void) -> void {
//  assert(static_cast<TERMINATOR>(trapped.TT) == TERMINATOR::INDIRECT_CALL);

#if defined(__x86_64__)
    gpr.rsp -= 8;
    ptrace::pokedata<false>(child, gpr.rsp, nextpc);
#elif defined(__i386__)
    gpr.esp -= 4;
    ptrace::pokedata<false>(child, gpr.esp, nextpc);
#elif defined(__aarch64__)
    gpr.regs[30 /* lr */] = nextpc;
#elif defined(__mips64) || defined(__mips__)
    gpr.regs[31 /* ra */] = nextnextpc;
#else
#error
#endif
  };
#endif

  //
  // determine the target address of the indirect control transfer and update
  // program counter accordingly
  //
  const uintptr_t TargetAddr = ({
#if defined(__mips64) || defined(__mips__)
    const unsigned r = Reg0;
    const uintptr_t TheTargetAddr = RegValue(r) & ~1UL;
    ptrace::pc_of_tracee_state(tracee_state) = emulate_delay_slot(r);
    TheTargetAddr;
#else
    emulate();
#endif
  });

#if 1
  switch (Opcode) {
#if defined(__x86_64__)
  case llvm::X86::CALL64m:
  case llvm::X86::CALL64r:
#elif defined(__i386__)
  case llvm::X86::CALL32m:
  case llvm::X86::CALL32r:
#elif defined(__aarch64__)
  case llvm::AArch64::BLR:
#elif defined(__mips64) || defined(__mips__)
  case llvm::Mips::JALR:
#else
#error
#endif
//  assert(trapped.IC);
    emulate_call();
    break;
  }
#endif

  return TargetAddr;
}

#undef JOVE_SINGLESTEP_OPCODE
