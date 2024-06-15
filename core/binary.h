#pragma once
#include <llvm/Object/Binary.h>

namespace jove {

std::unique_ptr<llvm::object::Binary> CreateBinary(llvm::StringRef Data);

llvm::object::OwningBinary<llvm::object::Binary>
CreateBinaryFromFile(const char *path);

}
