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

#include <boost/vmd/is_empty.hpp>
#include <boost/preprocessor/logical/or.hpp>
#include <boost/preprocessor/control/iif.hpp>

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
  llvm::SubtargetFeatures Features;

  if (IsMIPSTarget) {
#if defined(TARGET_MIPS64)
    Features.AddFeature("mips64r2");
#elif defined(TARGET_MIPS32)
    Features.AddFeature("mips32r2");
    //Features.AddFeature("o32");
#endif

    //Features.AddFeature("cpic");
    //Features.AddFeature("noreorder");
    //Features.AddFeature("pic");
  }

#ifdef TARGET_AARCH64
  Features.AddFeature("mte");
  Features.AddFeature("sve");
#endif

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
      TheTriple,
      BOOST_PP_IIF(BOOST_PP_OR(BOOST_VMD_IS_EMPTY(TARGET_X86_64),
                               BOOST_VMD_IS_EMPTY(TARGET_I386)),
                   1 /* Intel */, AsmInfo->getAssemblerDialect()),
      *AsmInfo, *MII, *MRI));

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
