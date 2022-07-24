#include "jove/jove.h"
#include "disas.h"
#include "triple.h"

#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>

#include <stdexcept>

namespace jove {

disas_t::disas_t() {
  //
  // Initialize targets and assembly printers/parsers.
  //
  llvm::InitializeAllTargets();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  //
  // initialize the LLVM objects necessary for disassembling instructions
  //
  llvm::Triple TheTriple = getTargetTriple();
  llvm::SubtargetFeatures Features; /* TODO mips? */

  std::string ArchName;
  std::string Error;

  TheTarget = llvm::TargetRegistry::lookupTarget(ArchName, TheTriple, Error);
  if (!TheTarget)
    throw std::runtime_error("failed to lookup target: " + Error);

  std::string TripleName = TheTriple.getTriple();
  std::string MCPU;

  MRI.reset(TheTarget->createMCRegInfo(TripleName));
  if (!MRI)
    throw std::runtime_error("no register info for target");

  {
    llvm::MCTargetOptions Options;
    AsmInfo.reset(TheTarget->createMCAsmInfo(*MRI, TripleName, Options));
    if (!AsmInfo)
      throw std::runtime_error("no assembly info");
  }

  STI.reset(TheTarget->createMCSubtargetInfo(TripleName, MCPU, Features.getString()));
  if (!STI)
    throw std::runtime_error("no subtarget info");

  MII.reset(TheTarget->createMCInstrInfo());
  if (!MII)
    throw std::runtime_error("no instruction info");

  MOFI = std::make_unique<llvm::MCObjectFileInfo>();
  MCCtx = std::make_unique<llvm::MCContext>(AsmInfo.get(), MRI.get(), MOFI.get());

  // FIXME: for now initialize MCObjectFileInfo with default values
  MOFI->InitMCObjectFileInfo(llvm::Triple(TripleName), false, *MCCtx);

  DisAsm.reset(TheTarget->createMCDisassembler(*STI, *MCCtx));
  if (!DisAsm)
    throw std::runtime_error("no disassembler for target");

  IP.reset(TheTarget->createMCInstPrinter(
      TheTriple, AsmInfo->getAssemblerDialect(), *AsmInfo, *MII, *MRI));

  if (!IP)
    throw std::runtime_error("no instruction printer for target");

  {
    llvm::TargetOptions Options;
    TM.reset(TheTarget->createTargetMachine(TripleName, MCPU,
                                            Features.getString(), Options,
                                            llvm::None));
  }
}

disas_t::~disas_t() {
}

}
