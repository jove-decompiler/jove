#include "B.h"

namespace jove {
namespace B {

std::unique_ptr<llvm::object::Binary> Create(llvm::StringRef Data) {
  llvm::Expected<std::unique_ptr<llvm::object::Binary>> BinOrErr =
      llvm::object::createBinary(llvm::MemoryBufferRef(Data, ""));

  if (!BinOrErr)
    throw std::runtime_error("failed to create binary: " +
                             llvm::toString(BinOrErr.takeError()));

  return std::move(*BinOrErr);
}

}
}
