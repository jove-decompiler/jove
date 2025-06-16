#pragma once
#include <llvm/IR/Module.h>

namespace jove {

void squashSRetFunctions(llvm::Module &);

}
