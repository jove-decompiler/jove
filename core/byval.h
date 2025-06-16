#pragma once
#include <llvm/IR/Module.h>

namespace jove {

void squashByvalFunctions(llvm::Module &);

}
