#pragma once
#include <jove/jove.h>
#include <llvm/ADT/Triple.h>

namespace jove {

llvm::Triple getTargetTriple(void);

}
