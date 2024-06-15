#pragma once
#include <llvm/Object/Binary.h>

namespace jove {
namespace B {

std::unique_ptr<llvm::object::Binary> Create(llvm::StringRef Data);

llvm::object::OwningBinary<llvm::object::Binary>
CreateFromFile(const char *path);

}
}
