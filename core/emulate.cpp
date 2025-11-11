#if (defined(__x86_64__)  && defined(TARGET_X86_64))  || \
    (defined(__i386__)    && defined(TARGET_I386))    || \
    (defined(__aarch64__) && defined(TARGET_AARCH64)) || \
    (defined(__mips64)    && defined(TARGET_MIPS64))  || \
    (defined(__mips__)    && defined(TARGET_MIPS32))
#include "emulate.h"
#include "ptrace.h"

#include <boost/format.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/repetition/repeat_from_to.hpp>

#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/Support/raw_ostream.h>

#define GET_INSTRINFO_ENUM
#include "LLVMGenInstrInfo.hpp"

#define GET_REGINFO_ENUM
#include "LLVMGenRegisterInfo.hpp"

#define WARN_ON(...)                                                           \
  do {                                                                         \
  } while (false)

namespace jove {

typedef boost::format fmt;

static std::string StringOfMCInst(disas_t &disas, const llvm::MCInst &Inst) {
  std::string res;

  {
    llvm::raw_string_ostream ss(res);

    disas.IP->printInst(&Inst, 0x0 /* XXX */, "", *disas.STI, ss);

#if 0
    ss << '\n';
    ss << "[opcode: " << Inst.getOpcode() << ']';
    for (unsigned i = 0; i < Inst.getNumOperands(); ++i) {
      const llvm::MCOperand &opnd = Inst.getOperand(i);

      char buff[0x100];
      if (opnd.isReg())
        snprintf(buff, sizeof(buff), "<reg %u>", opnd.getReg());
      else if (opnd.isImm())
        snprintf(buff, sizeof(buff), "<imm %" PRId64 ">", opnd.getImm());
      else if (opnd.isFPImm())
        snprintf(buff, sizeof(buff), "<imm %lf>", opnd.getFPImm());
      else if (opnd.isExpr())
        snprintf(buff, sizeof(buff), "<expr>");
      else if (opnd.isInst())
        snprintf(buff, sizeof(buff), "<inst>");
      else
        snprintf(buff, sizeof(buff), "<unknown>");

      ss << (fmt(" %u:%s") % i % buff).str();
    }

    ss << '\n';
#endif
  }

  return res;
}

#if defined(__mips64) || defined(__mips__)

static uint32_t code_cave_idx_of_reg(unsigned r) {
  switch (r) {
    case llvm::Mips::ZERO: return 0;
    case llvm::Mips::AT:   return 1;
    case llvm::Mips::V0:   return 2;
    case llvm::Mips::V1:   return 3;
    case llvm::Mips::A0:   return 4;
    case llvm::Mips::A1:   return 5;
    case llvm::Mips::A2:   return 6;
    case llvm::Mips::A3:   return 7;
    case llvm::Mips::T0:   return 8;
    case llvm::Mips::T1:   return 9;
    case llvm::Mips::T2:   return 10;
    case llvm::Mips::T3:   return 11;
    case llvm::Mips::T4:   return 12;
    case llvm::Mips::T5:   return 13;
    case llvm::Mips::T6:   return 14;
    case llvm::Mips::T7:   return 15;
    case llvm::Mips::S0:   return 16;
    case llvm::Mips::S1:   return 17;
    case llvm::Mips::S2:   return 18;
    case llvm::Mips::S3:   return 19;
    case llvm::Mips::S4:   return 20;
    case llvm::Mips::S5:   return 21;
    case llvm::Mips::S6:   return 22;
    case llvm::Mips::S7:   return 23;
    case llvm::Mips::T8:   return 24;
    case llvm::Mips::T9:   return 25;
    case llvm::Mips::K0:   return 26;
    case llvm::Mips::K1:   return 27;
    case llvm::Mips::GP:   return 28;
    case llvm::Mips::SP:   return 29;
    case llvm::Mips::FP:   return 30;
    case llvm::Mips::RA:   return 31;

    default:
      __builtin_trap();
      __builtin_unreachable();
  }
}

#endif

template <bool MT, bool MinSize>
uintptr_t
ptrace_emulator_t<MT, MinSize>::single_step(const pid_t child,
                                            const uintptr_t saved_pc,
                                            const trapped_t &trapped) {
  auto &gpr = this->tracee_state;

  //
  // define some helper functions for accessing the cpu state
  //
#if defined(__x86_64__)
  typedef unsigned long long RegValue_t;
#elif defined(__i386__)
  typedef long RegValue_t;
#elif defined(__aarch64__)
  typedef unsigned long long RegValue_t;
#elif defined(__mips64)
  typedef unsigned long RegValue_t;
#elif defined(__mips__)
  typedef unsigned long long RegValue_t;
#else
#error
#endif

  RegValue_t nextpc = saved_pc + trapped.IL;
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
    return ptrace::peekdata(child, addr);
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
      throw std::runtime_error(
          (fmt("RegValue: unknown llreg %u\n") % llreg).str());
    }
  };

#if defined(__mips64) || defined(__mips__)
  auto target_reg = [&](const llvm::MCInst &Inst) -> unsigned {
    if (Inst.getOpcode() == llvm::Mips::JALR) {
      assert(Inst.getNumOperands() == 2);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(0).getReg() == llvm::Mips::RA);
      assert(Inst.getOperand(1).isReg());
      return Inst.getOperand(1).getReg();
    }

    assert(Inst.getOpcode() == llvm::Mips::JR);
    assert(Inst.getNumOperands() == 1);
    assert(Inst.getOperand(0).isReg());
    return Inst.getOperand(0).getReg();
  };

  auto emulate_delay_slot = [&](const unsigned r,
                                const llvm::MCInst &I) -> uintptr_t {
    switch (I.getOpcode()) {
    default: { /* fallback to code cave XXX */
      if (IsVerbose())
        llvm::errs() << llvm::formatv("delayslot: {0} ({1})\n", I,
                                      StringOfMCInst(disas, I));

      aassert(ExecutableRegionAddress);

      unsigned idx = code_cave_idx_of_reg(r);
      uintptr_t jumpr_insn_addr = ExecutableRegionAddress +
                                  idx * (2 * sizeof(uint32_t));
      uintptr_t delay_slot_addr = jumpr_insn_addr  + sizeof(uint32_t);

      ptrace::pokedata(child, delay_slot_addr, trapped.DelaySlotInsn);
      return jumpr_insn_addr;
    }

    case llvm::Mips::LW:
    case llvm::Mips::SW: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      auto &Reg = RegValue(I.getOperand(0).getReg());
      long Base = RegValue(I.getOperand(1).getReg());
      long Offs = I.getOperand(2).getImm();
      long Addr = Base + Offs;

      if (I.getOpcode() == llvm::Mips::LW)
        Reg = ptrace::peekdata(child, Addr);
      else /* SW */
        ptrace::pokedata(child, Addr, Reg);

      break;
    }

    case llvm::Mips::LB: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      auto &Reg = RegValue(I.getOperand(0).getReg());
      long Base = RegValue(I.getOperand(1).getReg());
      long Offs = I.getOperand(2).getImm();
      long Addr = Base + Offs;

      unsigned long word = ptrace::peekdata(child, Addr);

      int8_t byte = *((int8_t *)&word);

      Reg = byte;
      break;
    }

    case llvm::Mips::LHu: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      long Base = RegValue(b);
      long Offs = I.getOperand(2).getImm();
      long Addr = Base + Offs;

      unsigned long word = ptrace::peekdata(child, Addr);

      static_assert(sizeof(word) >= sizeof(uint16_t));

      RegValue(a) = static_cast<unsigned long>(((uint16_t *)&word)[0]);
      break;
    }

    case llvm::Mips::SH: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      int64_t Base = RegValue(b);
      int64_t Offs = I.getOperand(2).getImm();
      int64_t Addr = Base + Offs;

      unsigned long word = ptrace::peekdata(child, Addr);
      ((uint16_t *)&word)[0] = RegValue(a);
      ptrace::pokedata(child, Addr, word);

      break;
    }

    case llvm::Mips::OR: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      RegValue(a) = RegValue(b) | RegValue(c);
      break;
    }

    case llvm::Mips::ADDiu: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      unsigned long x = I.getOperand(2).getImm();

      RegValue(a) = static_cast<unsigned long>(RegValue(b)) + x;
      break;
    }

    case llvm::Mips::ADDu: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      RegValue(a) = static_cast<unsigned long>(RegValue(b)) +
                    static_cast<unsigned long>(RegValue(c));
      break;
    }

    case llvm::Mips::SUBu: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      RegValue(a) = static_cast<unsigned long>(RegValue(b)) -
                    static_cast<unsigned long>(RegValue(c));
      break;
    }

    case llvm::Mips::SLL: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      unsigned long x = I.getOperand(2).getImm();

      RegValue(a) = static_cast<unsigned long>(RegValue(b)) << x;
      break;
    }

    case llvm::Mips::SRL: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      unsigned long x = I.getOperand(2).getImm();

      RegValue(a) = static_cast<unsigned long>(RegValue(b)) >> x;
      break;
    }

    case llvm::Mips::MOVZ_I_I: {
      assert(I.getNumOperands() == 4);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());
      assert(I.getOperand(3).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();
      unsigned d = I.getOperand(3).getReg();

      WARN_ON(a != d);

      if (RegValue(c) == 0)
        RegValue(a) = RegValue(b);

      break;
    }

    case llvm::Mips::MFLO: {
      assert(I.getNumOperands() == 1);
      assert(I.getOperand(0).isReg());

      unsigned a = I.getOperand(0).getReg();

      RegValue(a) = gpr.lo;
      break;
    }

    case llvm::Mips::XOR: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      RegValue(a) = RegValue(b) ^ RegValue(c);
      break;
    }

    case llvm::Mips::LUi: {
      assert(I.getNumOperands() == 2);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isImm());

      unsigned a = I.getOperand(0).getReg();

      unsigned long x = I.getOperand(1).getImm();

      RegValue(a) = x << 16;
      break;
    }

    case llvm::Mips::AND: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      RegValue(a) = RegValue(b) & RegValue(c);
      break;
    }

    case llvm::Mips::MUL: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      int64_t x = RegValue(b);
      int64_t y = RegValue(c);
      int64_t z = x * y;

      RegValue(a) = ((uint32_t *)&z)[0];
      break;
    }

    case llvm::Mips::SLTu: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();

      unsigned long x = RegValue(b);
      unsigned long y = RegValue(c);

      RegValue(a) = x < y;
      break;
    }

    case llvm::Mips::SLTiu: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      unsigned long x = I.getOperand(2).getImm();

      RegValue(a) = static_cast<unsigned long>(RegValue(b)) < x;
      break;
    }

    case llvm::Mips::SB: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      int64_t Base = RegValue(b);
      int64_t Offset = I.getOperand(2).getImm();
      int64_t Addr = Base + Offset;

      unsigned long word = ptrace::peekdata(child, Addr);
      ((uint8_t *)&word)[0] = RegValue(a);
      ptrace::pokedata(child, Addr, word);

      break;
    }

    case llvm::Mips::ORi: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      unsigned long x = I.getOperand(2).getImm();

      RegValue(a) = RegValue(b) | x;
      break;
    }

    case llvm::Mips::MOVN_I_I: {
      assert(I.getNumOperands() == 4);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isReg());
      assert(I.getOperand(3).isReg());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();
      unsigned c = I.getOperand(2).getReg();
      unsigned d = I.getOperand(3).getReg();

      WARN_ON(a != d);

      if (RegValue(c) != 0)
        RegValue(a) = RegValue(b);

      break;
    }

    case llvm::Mips::ANDi: {
      assert(I.getNumOperands() == 3);
      assert(I.getOperand(0).isReg());
      assert(I.getOperand(1).isReg());
      assert(I.getOperand(2).isImm());

      unsigned a = I.getOperand(0).getReg();
      unsigned b = I.getOperand(1).getReg();

      unsigned long x = I.getOperand(2).getImm();

      RegValue(a) = RegValue(b) & x;
      break;
    }

    case llvm::Mips::NOP:
      break;
    }

    if (IsVeryVerbose())
      llvm::errs() << llvm::formatv("emudelayslot: {0} ({1})\n", I,
                                    StringOfMCInst(disas, I));

    return RegValue(r) & ~1UL;
  };

#else

  auto emulate = [&](const llvm::MCInst &Inst) -> uintptr_t {
    switch (Inst.getOpcode()) {

#if defined(__x86_64__)

    case llvm::X86::CALL64m:
      assert(trapped.IC);
    case llvm::X86::JMP64m:
      assert(Inst.getNumOperands() == 5);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(1).isImm());
      assert(Inst.getOperand(2).isReg());
      assert(Inst.getOperand(3).isImm());
      assert(Inst.getOperand(4).isReg());

      if (Inst.getOperand(4).getReg() == llvm::X86::NoRegister) {
        unsigned x_r = Inst.getOperand(0).getReg();
        unsigned y_r = Inst.getOperand(2).getReg();

        long x = x_r == llvm::X86::NoRegister ? 0L : RegValue(x_r);
        long A = Inst.getOperand(1).getImm();
        long y = y_r == llvm::X86::NoRegister ? 0L : RegValue(y_r);
        long B = Inst.getOperand(3).getImm();

        return LoadAddr(x + A * y + B);
      } else {
        abort();
      }

    case llvm::X86::CALL64r:
      assert(trapped.IC);
    case llvm::X86::JMP64r:
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());

      return RegValue(Inst.getOperand(0).getReg());

    case llvm::X86::RET64: {
      uintptr_t res = LoadAddr(gpr.rsp);
      gpr.rsp += 8;

      if (Inst.getNumOperands() > 0) {
        assert(Inst.getNumOperands() == 1);
        assert(Inst.getOperand(0).isImm());

        gpr.rsp += Inst.getOperand(0).getImm();
      }

      return res;
    }

#elif defined(__i386__)

    case llvm::X86::CALL32m:
      assert(trapped.IC);
    case llvm::X86::JMP32m:
      assert(Inst.getNumOperands() == 5);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(1).isImm());
      assert(Inst.getOperand(2).isReg());
      assert(Inst.getOperand(3).isImm());
      assert(Inst.getOperand(4).isReg());

      if (Inst.getOperand(4).getReg() == llvm::X86::NoRegister) {
        unsigned x_r = Inst.getOperand(0).getReg();
        unsigned y_r = Inst.getOperand(2).getReg();

        long x = x_r == llvm::X86::NoRegister ? 0L : RegValue(x_r);
        long A = Inst.getOperand(1).getImm();
        long y = y_r == llvm::X86::NoRegister ? 0L : RegValue(y_r);
        long B = Inst.getOperand(3).getImm();

        return LoadAddr(x + A * y + B);
      } else {
        /* e.g. call dword ptr gs:[16] */
        return LoadAddr(RegValue(Inst.getOperand(4).getReg()) +
                        Inst.getOperand(3).getImm());
      }

    case llvm::X86::CALL32r:
      assert(trapped.IC);
    case llvm::X86::JMP32r:
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());

    case llvm::X86::RET32: { /* ret */
      uintptr_t res = LoadAddr(gpr.esp);
      gpr.esp += 4;

      if (Inst.getNumOperands() > 0) {
        assert(Inst.getNumOperands() == 1);
        assert(Inst.getOperand(0).isImm());

        gpr.esp += Inst.getOperand(0).getImm();
      }

      return res;
    }

#elif defined(__aarch64__)

    case llvm::AArch64::BLR:
      assert(trapped.IC);
    case llvm::AArch64::BR:
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());
      return RegValue(Inst.getOperand(0).getReg());

    case llvm::AArch64::RET: {
      if (Inst.getNumOperands() == 0)
        return gpr.regs[30 /* lr */];

      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());

      unsigned r = Inst.getOperand(0).getReg();
      return r == llvm::AArch64::NoRegister ? gpr.regs[30] : RegValue(r);
    }

#else
#error
#endif
    }

    auto &b = jv.Binaries.at(trapped.BIdx);
    auto &ICFG = b.Analysis.ICFG;
    auto bb = ICFG.vertex(trapped.BBIdx);

    throw std::runtime_error(
        "unknown opcode " + std::to_string(Inst.getOpcode()) + " @ " +
        taddr2str(ICFG[bb].Term.Addr) + " " + std::string(b.Name.c_str()) +
        " #operands=" + std::to_string(Inst.getNumOperands()));
  };
#endif

  auto emulate_call = [&](void) -> void {
    assert(static_cast<TERMINATOR>(trapped.TT) == TERMINATOR::INDIRECT_CALL);

#if defined(__x86_64__)
    gpr.rsp -= 8;
    ptrace::pokedata(child, gpr.rsp, nextpc);
#elif defined(__i386__)
    gpr.esp -= 4;
    ptrace::pokedata(child, gpr.esp, nextpc);
#elif defined(__aarch64__)
    gpr.regs[30 /* lr */] = nextpc;
#elif defined(__mips64) || defined(__mips__)
    gpr.regs[31 /* ra */] = nextnextpc;
#else
#error
#endif
  };

  //
  // determine the target address of the indirect control transfer and update
  // program counter accordingly
  //
  uintptr_t TheTargetAddr = ~0UL;

  ptrace::pc_of_tracee_state(this->tracee_state) = ({
#if defined(__mips64) || defined(__mips__)
    const unsigned r = target_reg(trapped.Inst);
    TheTargetAddr = RegValue(r) & ~1UL;
    emulate_delay_slot(r, trapped.DelaySlotInst);
#else
    (TheTargetAddr = emulate(trapped.Inst));
#endif
  });

  if (trapped.IC)
    emulate_call();

  return TheTargetAddr;
}

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template struct ptrace_emulator_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),  \
                                    GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))>;
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
#endif
