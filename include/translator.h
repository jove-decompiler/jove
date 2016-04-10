#pragma once
#include <config-target.h>
#include <inttypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/Object/ObjectFile.h>

namespace jove {

#if defined(TARGET_AARCH64) || defined(TARGET_X86_64)
typedef uint64_t address_t;
#else
typedef uint32_t address_t;
#endif

class translator {
  llvm::object::ObjectFile &O;

  llvm::LLVMContext& C;
  llvm::Module &M;
  const llvm::DataLayout &DL;

public:
  translator(llvm::object::ObjectFile &, llvm::LLVMContext &, llvm::Module &);
  ~translator();

  void translate(address_t);
};
}
