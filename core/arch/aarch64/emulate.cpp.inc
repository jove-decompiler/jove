using RegValue_t = unsigned long long;

#define REG_POSSIBILITIES \
    (llvm::AArch64::NoRegister) \
    (llvm::AArch64::X0)  \
    (llvm::AArch64::X1)  \
    (llvm::AArch64::X2)  \
    (llvm::AArch64::X3)  \
    (llvm::AArch64::X4)  \
    (llvm::AArch64::X5)  \
    (llvm::AArch64::X6)  \
    (llvm::AArch64::X7)  \
    (llvm::AArch64::X8)  \
    (llvm::AArch64::X9)  \
    (llvm::AArch64::X10) \
    (llvm::AArch64::X11) \
    (llvm::AArch64::X12) \
    (llvm::AArch64::X13) \
    (llvm::AArch64::X14) \
    (llvm::AArch64::X15) \
    (llvm::AArch64::X16) \
    (llvm::AArch64::X17) \
    (llvm::AArch64::X18) \
    (llvm::AArch64::X19) \
    (llvm::AArch64::X20) \
    (llvm::AArch64::X21) \
    (llvm::AArch64::X22) \
    (llvm::AArch64::X23) \
    (llvm::AArch64::X24) \
    (llvm::AArch64::X25) \
    (llvm::AArch64::X26) \
    (llvm::AArch64::X27) \
    (llvm::AArch64::X28) \
    (llvm::AArch64::FP)  \
    (llvm::AArch64::LR)  \
    (llvm::AArch64::SP)

#define JOVE_PARAM_DOMAIN_RetReg0 REG_POSSIBILITIES
#define JOVE_PARAM_DOMAIN_Reg0 REG_POSSIBILITIES

#define JOVE_SINGLESTEP_OPCODE BR
#define JOVE_SINGLESTEP_BR_PARAMETERS \
  ((unsigned, Reg0))
#include "single_step.cpp.inc"

#define JOVE_SINGLESTEP_OPCODE BLR
#define JOVE_SINGLESTEP_BLR_PARAMETERS \
  ((unsigned, Reg0))
#include "single_step.cpp.inc"

#define JOVE_SINGLESTEP_OPCODE RET
#define JOVE_SINGLESTEP_RET_PARAMETERS \
  ((unsigned, RetReg0))
#include "single_step.cpp.inc"

single_step_proc_t ptrace_emulation::load_single_step_proc(trapped_t &trapped, llvm::MCInst &Inst) {
  switch (Inst.getOpcode()) {
#define JOVE_SINGLESTEP_OPCODE BR
  case llvm::AArch64::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());

#include "load_single_step.cpp.inc"
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(0).getReg()
      ));
#undef JOVE_SINGLESTEP_OPCODE

#define JOVE_SINGLESTEP_OPCODE BLR
  case llvm::AArch64::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());

#include "load_single_step.cpp.inc"
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(0).getReg()
      ));
#undef JOVE_SINGLESTEP_OPCODE

#define JOVE_SINGLESTEP_OPCODE RET
  case llvm::AArch64::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 0 ||
             (Inst.getNumOperands() == 1 &&
              Inst.getOperand(0).isReg()));

#include "load_single_step.cpp.inc"
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
          Inst.getNumOperands() == 0 ? llvm::AArch64::LR
                                     : Inst.getOperand(0).getReg()
      ));
#undef JOVE_SINGLESTEP_OPCODE
  }

  throw unsupported_opcode_exception();
}
