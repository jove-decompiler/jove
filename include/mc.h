#pragma once

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

char* libmc_instr_asm(const void* code, uint64_t addr, char* out);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <llvm/Object/ObjectFile.h>
#include <llvm/MC/MCInstrAnalysis.h>

void libmc_init(const llvm::object::ObjectFile *Obj);
unsigned libmc_instr_opc(const void *code, uint64_t addr);
bool libmc_analyze_instr(llvm::MCInst &, uint64_t &size, const void *code,
                         uint64_t addr);
const llvm::MCInstrAnalysis *libmc_instranalyzer();
const llvm::MCInstrInfo *libmc_instrinfo();
const llvm::MCRegisterInfo *libmc_reginfo();
#endif
