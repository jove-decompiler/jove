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
namespace llvm {
namespace object {
class ObjectFile;
}
}

void libmc_init(const llvm::object::ObjectFile* Obj);
unsigned libmc_instr_opc(const void* code, uint64_t addr);
#endif
