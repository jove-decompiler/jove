#include "mc.h"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <config-target.h>
#include <iostream>
#include <llvm/ADT/Triple.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>

using namespace std;
using namespace llvm;
using namespace object;

namespace jove {

void libmc_init() {
#if defined(TARGET_AARCH64)
  LLVMInitializeAArch64TargetInfo();
  LLVMInitializeAArch64TargetMC();
  LLVMInitializeAArch64Disassembler();
#elif defined(TARGET_ARM)
  LLVMInitializeARMTargetInfo();
  LLVMInitializeARMTargetMC();
  LLVMInitializeARMDisassembler();
#elif defined(TARGET_X86_64)
  LLVMInitializeX86TargetInfo();
  LLVMInitializeX86TargetMC();
  LLVMInitializeX86Disassembler();
#elif defined(TARGET_I386)
  LLVMInitializeX86TargetInfo();
  LLVMInitializeX86TargetMC();
  LLVMInitializeX86Disassembler();
#elif defined(TARGET_MIPS)
  LLVMInitializeMipsTargetInfo();
  LLVMInitializeMipsTargetMC();
  LLVMInitializeMipsDisassembler();
#endif
}

mc_t::mc_t(const ObjectFile *Obj) : Obj(Obj), TheTriple(getArchTriple())
{
  if (Obj->isELF())
    TheTriple.setObjectFormat(Triple::ELF);
  if (Obj->isCOFF())
    TheTriple.setObjectFormat(Triple::COFF);
  if (Obj->isMachO())
    TheTriple.setObjectFormat(Triple::MachO);

  string Error;
  TheTarget = TargetRegistry::lookupTarget("", TheTriple, Error);

  assert(TheTarget);

  string TripleName = TheTriple.getTriple();
  MRI = TheTarget->createMCRegInfo(TripleName);
  AsmInfo = TheTarget->createMCAsmInfo(*MRI, TripleName);
  STI = TheTarget->createMCSubtargetInfo(TripleName, string(), string());
  MII = TheTarget->createMCInstrInfo();

  assert(MRI);
  assert(AsmInfo);
  assert(STI);
  assert(MII);

  MOFI = new MCObjectFileInfo;
#if 0
  Ctx = new MCContext(AsmInfo, MRI, MOFI);

  DisAsm = TheTarget->createMCDisassembler(*STI, *Ctx);
  assert(DisAsm);
  IP = TheTarget->createMCInstPrinter(
      Triple(TripleName), AsmInfo->getAssemblerDialect(), *AsmInfo, *MII, *MRI);
  assert(IP);
  IP->setPrintImmHex(true);

  MIA = TheTarget->createMCInstrAnalysis(MII);
#endif
}

llvm::Triple mc_t::getArchTriple() {
  llvm::Triple TheTriple("unknown-unknown-unknown");
  TheTriple.setArch(Triple::ArchType(Obj->getArch()));
  return TheTriple;
}

bool mc_t::analyze_instruction(MCInst &Inst, uint64_t &size,
                               const void *mcinsts, uint64_t addr) {
  return false;

  constexpr unsigned max_instr_len = 32;

  ArrayRef<uint8_t> coderef(static_cast<const uint8_t *>(mcinsts),
                            max_instr_len);

  raw_null_ostream nullos;
  return DisAsm->getInstruction(Inst, size, coderef, addr, nullos, nullos);
}

std::string mc_t::disassemble_instruction(const void *mcinst, uint64_t addr) {
  MCInst MI;
  uint64_t size;
  if (analyze_instruction(MI, size, mcinst, addr)) {
    string Str;
    {
      raw_string_ostream CvtOS(Str);
      IP->printInst(&MI, CvtOS, "", *STI);
    }

    boost::algorithm::trim(Str);
    boost::algorithm::replace_all(Str, "\t", " ");
    return Str;
  } else {
    return "<bad encoding>";
  }
}

}
