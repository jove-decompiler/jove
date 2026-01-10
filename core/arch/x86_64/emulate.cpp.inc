using RegValue_t = unsigned long long;

#define REG_POSSIBILITIES   \
    (llvm::X86::NoRegister) \
    (llvm::X86::RAX) \
    (llvm::X86::RBP) \
    (llvm::X86::RBX) \
    (llvm::X86::RCX) \
    (llvm::X86::RDI) \
    (llvm::X86::RDX) \
    (llvm::X86::RIP) \
    (llvm::X86::RSI) \
    (llvm::X86::RSP) \
    (llvm::X86::R8) \
    (llvm::X86::R9) \
    (llvm::X86::R10) \
    (llvm::X86::R11) \
    (llvm::X86::R12) \
    (llvm::X86::R13) \
    (llvm::X86::R14) \
    (llvm::X86::R15)

#define RETREG_POSSIBILITIES \
    (llvm::X86::RSP)

#define JOVE_PARAM_DOMAIN_RetReg0 RETREG_POSSIBILITIES
#define JOVE_PARAM_DOMAIN_Reg0 REG_POSSIBILITIES
#define JOVE_PARAM_DOMAIN_Reg1 REG_POSSIBILITIES
#define JOVE_PARAM_DOMAIN_Reg2 REG_POSSIBILITIES
#define JOVE_PARAM_DOMAIN_Reg3 REG_POSSIBILITIES
#define JOVE_PARAM_DOMAIN_Reg4 REG_POSSIBILITIES

#define JOVE_SINGLESTEP_OPCODE JMP64m
#define JOVE_SINGLESTEP_JMP64m_PARAMETERS \
  ((unsigned, Reg0))                      \
  ((unsigned, Reg2))
#include "single_step.cpp.inc"

#define JOVE_SINGLESTEP_OPCODE CALL64m
#define JOVE_SINGLESTEP_CALL64m_PARAMETERS \
  ((unsigned, Reg0))                       \
  ((unsigned, Reg2))
#include "single_step.cpp.inc"

#define JOVE_SINGLESTEP_OPCODE JMP64r
#define JOVE_SINGLESTEP_JMP64r_PARAMETERS \
  ((unsigned, Reg0))
#include "single_step.cpp.inc"

#define JOVE_SINGLESTEP_OPCODE CALL64r
#define JOVE_SINGLESTEP_CALL64r_PARAMETERS \
  ((unsigned, Reg0))
#include "single_step.cpp.inc"

#define JOVE_SINGLESTEP_OPCODE RET64
#define JOVE_SINGLESTEP_RET64_PARAMETERS \
  ((unsigned, RetReg0))
#include "single_step.cpp.inc"

single_step_proc_t ptrace_emulation::load_single_step_proc(trapped_t &trapped, llvm::MCInst &Inst) {
  switch (Inst.getOpcode()) {
#define JOVE_SINGLESTEP_OPCODE CALL64m
  case llvm::X86::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 5);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(1).isImm());
      assert(Inst.getOperand(2).isReg());
      assert(Inst.getOperand(3).isImm());
      assert(Inst.getOperand(4).isReg());
      assert(Inst.getOperand(4).getReg() == llvm::X86::NoRegister);

#include "load_single_step.cpp.inc"
      assert(Inst.getOperand(1).getImm() != 0);
      {
        uint64_t Scale = Inst.getOperand(1).getImm();
        aassert(Scale == 1 || Scale == 2 || Scale == 4 || Scale == 8);
        trapped.Scale = Scale;
      }
      trapped.Disp = Inst.getOperand(3).getImm();
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(0).getReg(),
                                    Inst.getOperand(2).getReg()
      ));
#undef JOVE_SINGLESTEP_OPCODE

#define JOVE_SINGLESTEP_OPCODE JMP64m
  case llvm::X86::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 5);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(1).isImm());
      assert(Inst.getOperand(2).isReg());
      assert(Inst.getOperand(3).isImm());
      assert(Inst.getOperand(4).isReg());
      assert(Inst.getOperand(4).getReg() == llvm::X86::NoRegister);

#include "load_single_step.cpp.inc"
      assert(Inst.getOperand(1).getImm() != 0);
      {
        uint64_t Scale = Inst.getOperand(1).getImm();
        aassert(Scale == 1 || Scale == 2 || Scale == 4 || Scale == 8);
        trapped.Scale = Scale;
      }
      trapped.Disp = Inst.getOperand(3).getImm();
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(0).getReg(),
                                    Inst.getOperand(2).getReg()
      ));
#undef JOVE_SINGLESTEP_OPCODE

#define JOVE_SINGLESTEP_OPCODE CALL64r
  case llvm::X86::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());

#include "load_single_step.cpp.inc"
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(0).getReg()
      ));
#undef JOVE_SINGLESTEP_OPCODE

#define JOVE_SINGLESTEP_OPCODE JMP64r
  case llvm::X86::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());

#include "load_single_step.cpp.inc"
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(0).getReg()
      ));
#undef JOVE_SINGLESTEP_OPCODE

#define JOVE_SINGLESTEP_OPCODE RET64
  case llvm::X86::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 0 ||
             (Inst.getNumOperands() == 1 &&
              Inst.getOperand(0).isImm()));

      trapped.Disp = Inst.getNumOperands() == 1 ? Inst.getOperand(0).getImm() : 0;
#include "load_single_step.cpp.inc"
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    llvm::X86::RSP
      ));
#undef JOVE_SINGLESTEP_OPCODE
  }

  throw unsupported_opcode_exception();
}
