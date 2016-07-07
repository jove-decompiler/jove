#pragma once
#include <llvm/ADT/Triple.h>

#ifndef __cplusplus
#error "no can do"
#endif

namespace llvm {
class AsmPrinter;
class MCAsmBackend;
class MCAsmInfo;
class MCAsmParser;
class MCCodeEmitter;
class MCCodeGenInfo;
class MCContext;
class MCDisassembler;
class MCInstrAnalysis;
class MCInstPrinter;
class MCInstrInfo;
class MCRegisterInfo;
class MCStreamer;
class MCSubtargetInfo;
class MCSymbolizer;
class MCRelocationInfo;
class MCTargetAsmParser;
class MCTargetOptions;
class MCTargetStreamer;
class TargetMachine;
class TargetOptions;
class raw_ostream;
class raw_pwrite_stream;
class formatted_raw_ostream;
class Target;
class MCObjectFileInfo;
class MCInst;
namespace object {
class ObjectFile;
}
}

namespace jove {

void libmc_init();

class mc_t {
  const llvm::object::ObjectFile* Obj;

  llvm::Triple TheTriple;
  const llvm::Target* TheTarget;

  virtual llvm::Triple getArchTriple();

public:
  const llvm::MCRegisterInfo *MRI;
  const llvm::MCAsmInfo *AsmInfo;
  const llvm::MCSubtargetInfo *STI;
  const llvm::MCInstrInfo *MII;
  const llvm::MCInstrAnalysis *MIA;
  const llvm::MCObjectFileInfo *MOFI;
  llvm::MCContext *Ctx;
  llvm::MCDisassembler *DisAsm;
  llvm::MCInstPrinter *IP;

  mc_t(const llvm::object::ObjectFile *Obj);

  bool analyze_instruction(llvm::MCInst &, uint64_t &size, const void *mcinsts,
                           uint64_t addr);
  std::string disassemble_instruction(const void *mcinst, uint64_t addr);
};

#if !defined(TARGET_AARCH64) && defined(TARGET_ARM)
class thumb_mc_t : public mc_t {
  virtual llvm::Triple getArchTriple() {
    return llvm::Triple("thumbv7-unknown-unknown");
  }
public:
  thumb_mc_t(const llvm::object::ObjectFile *Obj) : mc_t(Obj) {}
};
#endif

}
