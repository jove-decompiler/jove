#include "B.h"
#include "triple.h"
#include <llvm/ADT/StringRef.h>

namespace jove {
namespace B {

static llvm::StringRef
getObjectFormatTypeName(llvm::Triple::ObjectFormatType Kind) {
  switch (Kind) {
  case llvm::Triple::UnknownObjectFormat:
    return "";
  case llvm::Triple::COFF:
    return "coff";
  case llvm::Triple::ELF:
    return "elf";
  case llvm::Triple::GOFF:
    return "goff";
  case llvm::Triple::MachO:
    return "macho";
  case llvm::Triple::Wasm:
    return "wasm";
  case llvm::Triple::XCOFF:
    return "xcoff";
  case llvm::Triple::DXContainer:
    return "dxcontainer";
  case llvm::Triple::SPIRV:
    return "spirv";
  }
  llvm_unreachable("unknown object format type");
}

std::unique_ptr<llvm::object::Binary> Create(llvm::StringRef Data) {
  llvm::Expected<std::unique_ptr<llvm::object::Binary>> BinOrErr =
      llvm::object::createBinary(llvm::MemoryBufferRef(Data, ""));

  if (!BinOrErr)
    throw std::runtime_error("failed to create binary: " +
                             llvm::toString(BinOrErr.takeError()));

  std::unique_ptr<llvm::object::Binary> &Bin = BinOrErr.get();
  if (!llvm::isa<ELFO>(Bin.get()) &&
      (!llvm::isa<COFFO>(Bin.get()) ||
       llvm::cast<COFFO>(Bin.get())->getBytesInAddress() != sizeof(taddr_t)))
    throw std::runtime_error(
        "unexpected binary type (" + std::to_string(Bin->getType()) + ") [" +
        getObjectFormatTypeName(Bin->getTripleObjectFormat()).str());

  return std::move(*BinOrErr);
}

}
}
