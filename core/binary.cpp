#include "binary.h"
#include "elf.h"

namespace obj = llvm::object;

namespace jove {
namespace B {

std::unique_ptr<llvm::object::Binary> Create(llvm::StringRef Data) {
  llvm::Expected<std::unique_ptr<llvm::object::Binary>> BinOrErr =
      llvm::object::createBinary(llvm::MemoryBufferRef(Data, ""));

  if (!BinOrErr)
    throw std::runtime_error("CreateBinary failed: " +
                             llvm::toString(BinOrErr.takeError()));

  return std::move(*BinOrErr);
}

llvm::object::OwningBinary<obj::Binary>
CreateFromFile(const char *path) {
  auto BinOrErr = llvm::object::createBinary(path);
  if (!BinOrErr)
    throw std::runtime_error("CreateBinaryFromFile failed: " +
                             llvm::toString(BinOrErr.takeError()));

  obj::OwningBinary<obj::Binary> &res = *BinOrErr;
  if (!llvm::isa<ELFO>(res.getBinary()))
    throw std::runtime_error("CreateBinaryFromFile: unknown architecture");

  return std::move(res);
}

}
}
