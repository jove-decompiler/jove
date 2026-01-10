using RegValue_t = long;

#define GPRREG_POSSIBILITIES \
    (llvm::X86::NoRegister) \
    (llvm::X86::EAX) \
    (llvm::X86::EBP) \
    (llvm::X86::EBX) \
    (llvm::X86::ECX) \
    (llvm::X86::EDI) \
    (llvm::X86::EDX) \
    (llvm::X86::EIP) \
    (llvm::X86::ESI) \
    (llvm::X86::ESP)

#define SEGREG_POSSIBILITIES \
    (llvm::X86::NoRegister) \
    (llvm::X86::SS) \
    (llvm::X86::CS) \
    (llvm::X86::DS) \
    (llvm::X86::ES) \
    (llvm::X86::FS) \
    (llvm::X86::GS)

#define RETREG_POSSIBILITIES \
    (llvm::X86::ESP)

#define JOVE_PARAM_DOMAIN_RetReg0 RETREG_POSSIBILITIES
#define JOVE_PARAM_DOMAIN_Reg0 GPRREG_POSSIBILITIES
#define JOVE_PARAM_DOMAIN_Reg1 GPRREG_POSSIBILITIES
#define JOVE_PARAM_DOMAIN_Reg2 GPRREG_POSSIBILITIES
#define JOVE_PARAM_DOMAIN_Reg3 GPRREG_POSSIBILITIES
#define JOVE_PARAM_DOMAIN_Reg4 SEGREG_POSSIBILITIES

#define JOVE_SINGLESTEP_OPCODE JMP32m
#define JOVE_SINGLESTEP_JMP32m_PARAMETERS \
  ((unsigned, Reg0))                      \
  ((unsigned, Reg2))                      \
  ((unsigned, Reg4))
#include "single_step.cpp.inc"

#define JOVE_SINGLESTEP_OPCODE CALL32m
#define JOVE_SINGLESTEP_CALL32m_PARAMETERS \
  ((unsigned, Reg0))                       \
  ((unsigned, Reg2))                       \
  ((unsigned, Reg4))
#include "single_step.cpp.inc"

#define JOVE_SINGLESTEP_OPCODE JMP32r
#define JOVE_SINGLESTEP_JMP32r_PARAMETERS \
  ((unsigned, Reg0))
#include "single_step.cpp.inc"

#define JOVE_SINGLESTEP_OPCODE CALL32r
#define JOVE_SINGLESTEP_CALL32r_PARAMETERS \
  ((unsigned, Reg0))
#include "single_step.cpp.inc"

#define JOVE_SINGLESTEP_OPCODE RET32
#define JOVE_SINGLESTEP_RET32_PARAMETERS \
  ((unsigned, RetReg0))
#include "single_step.cpp.inc"

#define JOVE_SINGLESTEP_OPCODE RETI32
#define JOVE_SINGLESTEP_RETI32_PARAMETERS \
  ((unsigned, RetReg0))
#include "single_step.cpp.inc"

single_step_proc_t ptrace_emulation::load_single_step_proc(trapped_t &trapped, llvm::MCInst &Inst) {
  switch (Inst.getOpcode()) {
#define JOVE_SINGLESTEP_OPCODE CALL32m
  case llvm::X86::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 5);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(1).isImm());
      assert(Inst.getOperand(2).isReg());
      assert(Inst.getOperand(3).isImm());
      assert(Inst.getOperand(4).isReg());

#include "load_single_step.cpp.inc"
      assert(Inst.getOperand(1).getImm() != 0);
      {
        const uint64_t Scale = Inst.getOperand(1).getImm();
        aassert(Scale == 1 || Scale == 2 || Scale == 4 || Scale == 8);
        trapped.Scale = Scale;
      }
      trapped.Disp  = Inst.getOperand(3).getImm();
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(0).getReg(),
                                    Inst.getOperand(2).getReg(),
                                    Inst.getOperand(4).getReg()
      ));
#undef JOVE_SINGLESTEP_OPCODE

#define JOVE_SINGLESTEP_OPCODE JMP32m
  case llvm::X86::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 5);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(1).isImm());
      assert(Inst.getOperand(2).isReg());
      assert(Inst.getOperand(3).isImm());
      assert(Inst.getOperand(4).isReg());

#include "load_single_step.cpp.inc"
      assert(Inst.getOperand(1).getImm() != 0);
      {
        const uint64_t Scale = Inst.getOperand(1).getImm();
        aassert(Scale == 1 || Scale == 2 || Scale == 4 || Scale == 8);
        trapped.Scale = Scale;
      }
      trapped.Disp = Inst.getOperand(3).getImm();
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(0).getReg(),
                                    Inst.getOperand(2).getReg(),
                                    Inst.getOperand(4).getReg()
      ));
#undef JOVE_SINGLESTEP_OPCODE

#define JOVE_SINGLESTEP_OPCODE CALL32r
  case llvm::X86::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());

#include "load_single_step.cpp.inc"
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(0).getReg()
      ));
#undef JOVE_SINGLESTEP_OPCODE

#define JOVE_SINGLESTEP_OPCODE JMP32r
  case llvm::X86::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());

#include "load_single_step.cpp.inc"
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(0).getReg()
      ));
#undef JOVE_SINGLESTEP_OPCODE

#define JOVE_SINGLESTEP_OPCODE RET32
  case llvm::X86::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 0);

      trapped.Disp = 0;
#include "load_single_step.cpp.inc"
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    llvm::X86::ESP
      ));
#undef JOVE_SINGLESTEP_OPCODE

#define JOVE_SINGLESTEP_OPCODE RETI32
  case llvm::X86::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 1 &&
             Inst.getOperand(0).isImm());

      trapped.Disp = Inst.getOperand(0).getImm();
#include "load_single_step.cpp.inc"
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    llvm::X86::ESP
      ));
#undef JOVE_SINGLESTEP_OPCODE
  }

  throw unsupported_opcode_exception();
}
