#include <config-target.h>
#include "mc.h"
#include <llvm/ADT/Triple.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/COFF.h>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <iostream>

using namespace std;
using namespace llvm;
using namespace object;

static const MCRegisterInfo *MRI;
static const MCAsmInfo *AsmInfo;
static const MCSubtargetInfo *STI;
static const MCInstrInfo *MII;
static const MCObjectFileInfo *MOFI;
static MCContext *Ctx;
static MCDisassembler *DisAsm;
static const MCInstrAnalysis *MIA;
static MCInstPrinter *IP;

static string TripleName;
static const Target *getTarget(const ObjectFile *Obj = nullptr);
static uint64_t libmc_disas(MCInst &MI, const void *code, uint64_t addr);
static const unsigned max_instr_len = 24;

void libmc_init(const ObjectFile *Obj) {
  // Initialize targets and assembly printers/parsers.
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

  const Target *TheTarget = getTarget(Obj);

  // Package up features to be passed to target/subtarget
  string MCPU;
  string FeaturesStr;
#if 0
  if (MAttrs.size()) {
    SubtargetFeatures Features;
    for (unsigned i = 0; i != MAttrs.size(); ++i)
      Features.AddFeature(MAttrs[i]);
    FeaturesStr = Features.getString();
  }
#endif

  MRI = TheTarget->createMCRegInfo(TripleName);
  if (!MRI)
    exit(29);
  AsmInfo = TheTarget->createMCAsmInfo(*MRI, TripleName);
  if (!AsmInfo)
    exit(30);
  STI = TheTarget->createMCSubtargetInfo(TripleName, MCPU, FeaturesStr);
  if (!STI)
    exit(31);
  MII = TheTarget->createMCInstrInfo();
  if (!MII)
    exit(32);

  MOFI = new MCObjectFileInfo;
  Ctx = new MCContext(AsmInfo, MRI, MOFI);

  DisAsm = TheTarget->createMCDisassembler(*STI, *Ctx);
  if (!DisAsm)
    exit(33);

  /* may be null for unsupported targets */
  MIA = TheTarget->createMCInstrAnalysis(MII);

  IP = TheTarget->createMCInstPrinter(Triple(TripleName),
#ifdef TARGET_I386
                                      1, // intel asm
#else
                                      AsmInfo->getAssemblerDialect(),
#endif
                                      *AsmInfo, *MII, *MRI);

  if (!IP)
    exit(35);

  IP->setPrintImmHex(true);
}

unsigned libmc_instr_opc(const void *code, uint64_t addr) {
  MCInst MI;
  libmc_disas(MI, code, addr);
  return MI.getOpcode();
}

char* libmc_instr_asm(const void *code, uint64_t addr, char* out) {
  MCInst MI;
  libmc_disas(MI, code, addr);

  string Str;
  {
    raw_string_ostream CvtOS(Str);
    IP->printInst(&MI, CvtOS, "", *STI);
  }

  boost::algorithm::trim(Str);
  boost::algorithm::replace_all(Str, "\t", " ");
  strcpy(out, Str.c_str());

  return out;
}

uint64_t libmc_disas(MCInst &Inst, const void *code, uint64_t addr) {
  uint64_t instrlen;
  ArrayRef<uint8_t> coderef(static_cast<const uint8_t*>(code), max_instr_len);

  raw_null_ostream nullos;
  if (!DisAsm->getInstruction(Inst, instrlen, coderef, addr, nullos, nullos)) {
    errs().flush();
    exit(34);
  }

  return instrlen;
}

uint64_t libmc_analyze_instr(MCInst &Instr, const void *code,
                                           uint64_t addr) {
  return libmc_disas(Instr, code, addr);
}

const MCInstrAnalysis *libmc_instranalyzer() { return MIA; }

const MCInstrInfo *libmc_instrinfo() { return MII; }

const MCRegisterInfo *libmc_reginfo() { return MRI; }

const Target *getTarget(const ObjectFile *Obj) {
  // Figure out the target triple.
  llvm::Triple TheTriple("unknown-unknown-unknown");

  if (Obj->getArch() != Triple::arm)
    TheTriple.setArch(Triple::ArchType(Obj->getArch()));
  else
    TheTriple.setTriple("thumbv7-unknown-unknown");

  if (Obj->isELF())
    TheTriple.setObjectFormat(Triple::ELF);
  if (Obj->isCOFF())
    TheTriple.setObjectFormat(Triple::COFF);
  if (Obj->isMachO())
    TheTriple.setObjectFormat(Triple::MachO);

  // Get the target specific parser.
  std::string Error;
  const Target *TheTarget = TargetRegistry::lookupTarget("", TheTriple, Error);
  if (!TheTarget)
    exit(35);

  // Update the triple name and return the found target.
  TripleName = TheTriple.getTriple();
  return TheTarget;
}
