#pragma once
#include <llvm/IR/LLVMContext.h>
#include <memory>

namespace jove {

struct SafeLLVMContext {
  llvm::LLVMContext Context;
  std::mutex Mtx;
};

}
