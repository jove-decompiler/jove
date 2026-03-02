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
    ptrace::target_tracee_state_t &tracee_state,
    trapped_t &trapped,
    ptrace_emulator_t &emu
) noexcept {
  auto &gpr = tracee_state;

  const taddr_t savedpc = tracee_state.program_counter();
  const taddr_t nextpc = savedpc + static_cast<taddr_t>(trapped.IL);
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  const taddr_t nextnextpc = nextpc + 4;
#endif

  auto LoadAddr = [&](taddr_t addr) -> taddr_t {
    try {
      taddr_t res = 0;
      ssize_t got = emu.tool.peek(addr, (uint8_t *)&res, sizeof(res));
      assert(got == sizeof(res));
      return res;
    } catch (const ptrace::tracer_exception &x) {}
    abort();
  };

  auto RegValue = [&](unsigned llreg) -> taddr_t {
    switch (llreg) {
#if defined(TARGET_X86_64)
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

#elif defined(TARGET_I386)

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
#define SEGREG_CASE(name, ucname)                                              \
  case llvm::X86::ucname: {                                                    \
    taddr_t base = emu.BOOST_PP_CAT(name,_base);                               \
    if (unlikely(!(~base)))                                                    \
      emu.BOOST_PP_CAT(name,_base) = base =                                    \
          ptrace::segment_address_of_selector(emu.tool._child,                 \
                                              gpr.BOOST_PP_CAT(x,name));       \
    return base;                                                               \
  }

    SEGREG_CASE(ss, SS)
    SEGREG_CASE(cs, CS)
    SEGREG_CASE(ds, DS)
    SEGREG_CASE(es, ES)
    SEGREG_CASE(fs, FS)
    SEGREG_CASE(gs, GS)

#undef SEGREG_CASE

#elif defined(TARGET_AARCH64)

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

#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)

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

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  auto emulate_delay_slot = [&](const unsigned r) -> uintptr_t {
    if constexpr (DelaySlotOpcode == llvm::Mips::INSTRUCTION_LIST_END) {
      unsigned idx = code_cave_idx_of_reg(r);
      uintptr_t jumpr_insn_addr = emu.ExecutableRegionAddress +
                                  idx * (2 * sizeof(ptrace::word));
      uintptr_t delay_slot_addr = jumpr_insn_addr + 4;

      if (sizeof(ptrace::word) == 8) {
        uint32_t insns[2] = {encoding_of_jump_to_reg(reg_of_idx(idx)),
                             trapped.DelaySlotInsn};

        static_assert(sizeof(insns) == 8);

        ptrace::word the_poke;
        __builtin_memcpy_inline(&the_poke, &insns[0], sizeof(the_poke));
        ptrace::pokedata(emu.tool._child, jumpr_insn_addr, the_poke);
      } else if constexpr (sizeof(ptrace::word) == 4) {
        ptrace::pokedata(emu.tool._child, delay_slot_addr,
                         trapped.DelaySlotInsn);
      } else {
        __compiletime_unreachable();
      }

      return jumpr_insn_addr;
    }

    __compiletime_unreachable();
  };

#else

  auto emulate = [&](void) -> uintptr_t {
#if defined(TARGET_X86_64)
    if constexpr (Opcode == llvm::X86::JMP64r ||
                  Opcode == llvm::X86::CALL64r) {
      return RegValue(Reg0);
    }

    if constexpr (Opcode == llvm::X86::JMP64m ||
                  Opcode == llvm::X86::CALL64m) {
      unsigned x_r = Reg0;
      unsigned y_r = Reg2;

      long x = x_r == llvm::X86::NoRegister ? 0L : RegValue(x_r);
      long A = trapped.Scale;
      long y = y_r == llvm::X86::NoRegister ? 0L : RegValue(y_r);
      long B = trapped.Disp;

      return LoadAddr(x + A * y + B);
    }

    if constexpr (Opcode == llvm::X86::RET64) {
      uintptr_t res = LoadAddr(RegValue(RetReg0));
      gpr.rsp += (8 + trapped.Disp);
      return res;
    }

#elif defined(TARGET_I386)
    if constexpr (Opcode == llvm::X86::JMP32r ||
                  Opcode == llvm::X86::CALL32r) {
      return RegValue(Reg0);
    }

    if constexpr (Opcode == llvm::X86::JMP32m ||
                  Opcode == llvm::X86::CALL32m) {
      if (Reg0 == llvm::X86::NoRegister &&
          Reg2 == llvm::X86::NoRegister &&
          Reg4 == llvm::X86::NoRegister) {
        return LoadAddr(static_cast<uint32_t>(trapped.Disp));
      }

      uint32_t disp   = static_cast<uint32_t>(static_cast<uint64_t>(trapped.Disp));
      uint32_t base  = Reg0 == llvm::X86::NoRegister ? UINT32_C(0) : static_cast<uint32_t>(RegValue(Reg0));
      uint32_t index = Reg2 == llvm::X86::NoRegister ? UINT32_C(0) : static_cast<uint32_t>(RegValue(Reg2));
      uint32_t scale = static_cast<uint32_t>(static_cast<int32_t>(trapped.Scale));
      uint32_t seg = Reg4 == llvm::X86::NoRegister ? UINT32_C(0) : static_cast<uint32_t>(RegValue(Reg4));

      uint32_t ea = static_cast<uint32_t>(base + scale * index + disp);

      return LoadAddr(ea + seg);
    }

    if constexpr (Opcode == llvm::X86::RET32) {
      const uint32_t sp = gpr.esp;

      uint32_t res = LoadAddr(sp);
      *reinterpret_cast<uint32_t *>(&gpr.esp) = sp + 4u;
      return res;
    }

    if constexpr (Opcode == llvm::X86::RETI32) {
      const uint32_t sp = gpr.esp;

      uint32_t res = LoadAddr(sp);
      *reinterpret_cast<uint32_t *>(&gpr.esp) = sp + 4u + static_cast<uint32_t>(static_cast<int32_t>(trapped.Disp));
      return res;
    }

#elif defined(TARGET_AARCH64)

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

#if defined(TARGET_X86_64) || defined(TARGET_I386)
    const taddr_t newsp =
        static_cast<taddr_t>(gpr.stack_pointer()) - sizeof(taddr_t);
    gpr.stack_pointer() = newsp;
    try {
      auto wrote = emu.tool.poke(
          newsp, reinterpret_cast<const uint8_t *>(&nextpc), sizeof(nextpc));
      assert(wrote == sizeof(nextpc));
      return;
    } catch (const ptrace::tracer_exception &) {
    }
    abort();
#elif defined(TARGET_AARCH64)
    gpr.regs[30 /* lr */] = nextpc;
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
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
  const taddr_t TargetAddr = ({
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    const unsigned r = Reg0;
    const taddr_t TheTargetAddr = RegValue(r) & ~1UL;
    tracee_state.program_counter() = emulate_delay_slot(r);
    TheTargetAddr;
#else
    emulate();
#endif
  });

#if 1
  switch (Opcode) {
  default:
    break;
#if defined(TARGET_X86_64)
  case llvm::X86::CALL64m:
  case llvm::X86::CALL64r:
#elif defined(TARGET_I386)
  case llvm::X86::CALL32m:
  case llvm::X86::CALL32r:
#elif defined(TARGET_AARCH64)
  case llvm::AArch64::BLR:
#elif defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
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
