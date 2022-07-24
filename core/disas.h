#pragma once
#include <memory>

namespace llvm {
class MCAsmInfo;
class MCContext;
class MCDisassembler;
class MCInstPrinter;
class MCInstrInfo;
class MCObjectFileInfo;
class MCRegisterInfo;
class MCSubtargetInfo;
class Target;
class TargetMachine;
}

namespace jove {

//
// this class encapsulates all the LLVM objects required for disassembling
// machine code
//
struct disas_t {
  disas_t();
  ~disas_t();

  const llvm::Target *TheTarget;
  std::unique_ptr<const llvm::MCRegisterInfo> MRI;
  std::unique_ptr<const llvm::MCAsmInfo> AsmInfo;
  std::unique_ptr<const llvm::MCSubtargetInfo> STI;
  std::unique_ptr<const llvm::MCInstrInfo> MII;
  std::unique_ptr<llvm::MCObjectFileInfo> MOFI;
  std::unique_ptr<llvm::MCContext> MCCtx;
  std::unique_ptr<llvm::MCDisassembler> DisAsm;
  std::unique_ptr<llvm::MCInstPrinter> IP;
  std::unique_ptr<llvm::TargetMachine> TM;
};

}
