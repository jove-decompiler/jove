using RegValue_t = unsigned long;

#define REG_POSSIBILITIES \
    (llvm::Mips::ZERO) \
    (llvm::Mips::AT) \
    (llvm::Mips::V0) \
    (llvm::Mips::V1) \
    (llvm::Mips::A0) \
    (llvm::Mips::A1) \
    (llvm::Mips::A2) \
    (llvm::Mips::A3) \
    (llvm::Mips::T0) \
    (llvm::Mips::T1) \
    (llvm::Mips::T2) \
    (llvm::Mips::T3) \
    (llvm::Mips::T4) \
    (llvm::Mips::T5) \
    (llvm::Mips::T6) \
    (llvm::Mips::T7) \
    (llvm::Mips::S0) \
    (llvm::Mips::S1) \
    (llvm::Mips::S2) \
    (llvm::Mips::S3) \
    (llvm::Mips::S4) \
    (llvm::Mips::S5) \
    (llvm::Mips::S6) \
    (llvm::Mips::S7) \
    (llvm::Mips::T8) \
    (llvm::Mips::T9) \
    (llvm::Mips::GP) \
    (llvm::Mips::SP) \
    (llvm::Mips::FP) \
    (llvm::Mips::RA)

#if 0

    (llvm::Mips::LW)       \
    (llvm::Mips::SW)       \
    (llvm::Mips::LB)       \
    (llvm::Mips::LHu)      \
    (llvm::Mips::SH)       \
    (llvm::Mips::OR)       \
    (llvm::Mips::ADDiu)    \
    (llvm::Mips::ADDu)     \
    (llvm::Mips::SUBu)     \
    (llvm::Mips::SLL)      \
    (llvm::Mips::SRL)      \
    (llvm::Mips::MOVZ_I_I) \
    (llvm::Mips::MFLO)     \
    (llvm::Mips::XOR)      \
    (llvm::Mips::LUi)      \
    (llvm::Mips::AND)      \
    (llvm::Mips::MUL)      \
    (llvm::Mips::SLTu)     \
    (llvm::Mips::SLTiu)    \
    (llvm::Mips::SB)       \
    (llvm::Mips::ORi)      \
    (llvm::Mips::MOVN_I_I) \
    (llvm::Mips::ANDi)     \
    (llvm::Mips::NOP)      \

#endif

#define DELAYSLOTOPCODE_POSSIBILITIES \
    (llvm::Mips::INSTRUCTION_LIST_END)

#define JOVE_PARAM_DOMAIN_Reg0 REG_POSSIBILITIES
#define JOVE_PARAM_DOMAIN_DelaySlotOpcode DELAYSLOTOPCODE_POSSIBILITIES

#define JOVE_SINGLESTEP_OPCODE JR
#define JOVE_SINGLESTEP_JR_PARAMETERS \
  ((unsigned, Reg0))                  \
  ((unsigned, DelaySlotOpcode))
#include "single_step.cpp.inc"

#define JOVE_SINGLESTEP_OPCODE JALR
#define JOVE_SINGLESTEP_JALR_PARAMETERS \
  ((unsigned, Reg0))                    \
  ((unsigned, DelaySlotOpcode))
#include "single_step.cpp.inc"

single_step_proc_t
ptrace_emulation::load_single_step_proc(trapped_t &trapped,
                                        llvm::MCInst &Inst,
                                        llvm::MCInst &DelaySlotInst) {
  switch (Inst.getOpcode()) {
#define JOVE_SINGLESTEP_OPCODE JR
  case llvm::Mips::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 1);
      assert(Inst.getOperand(0).isReg());

#include "load_single_step.cpp.inc"
#if 0
      try {
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(0).getReg(),
                                    DelaySlotInst.getOpcode()
      ));
      } catch (const std::out_of_range &) {
#endif /* delay slot emulation FIXME */
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(0).getReg(),
                                    llvm::Mips::INSTRUCTION_LIST_END
      ));
#if 0
      }
#endif /* delay slot emulation FIXME */
#undef JOVE_SINGLESTEP_OPCODE

#define JOVE_SINGLESTEP_OPCODE JALR
  case llvm::Mips::JOVE_SINGLESTEP_OPCODE:
      assert(Inst.getNumOperands() == 2);
      assert(Inst.getOperand(0).isReg());
      assert(Inst.getOperand(0).getReg() == llvm::Mips::RA);
      assert(Inst.getOperand(1).isReg());

#include "load_single_step.cpp.inc"
#if 0
      try {
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(1).getReg(),
                                    DelaySlotInst.getOpcode()
      ));
      } catch (const std::out_of_range &) {
#endif /* delay slot emulation FIXME */
      return JOVE_SINGLESTEP_MAP.at(JOVE_SINGLESTEP_MAP_KEY_TYPE(
                                    Inst.getOperand(1).getReg(),
                                    llvm::Mips::INSTRUCTION_LIST_END
      ));
#if 0
      }
#endif /* delay slot emulation FIXME */
#undef JOVE_SINGLESTEP_OPCODE
  }

  throw unsupported_opcode_exception();
}
