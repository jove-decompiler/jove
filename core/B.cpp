#include "B.h"
#include "triple.h"

#include <llvm/ADT/StringRef.h>
#include <llvm/IR/LLVMContext.h>

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
  static std::conditional_t<AreWeMT, std::mutex, std::monostate> ContextMtx;
  static std::unique_ptr<llvm::LLVMContext> Context;

  std::unique_ptr<llvm::object::Binary> TheBin;
  {
    std::conditional_t<AreWeMT, std::unique_lock<std::mutex>, __do_nothing_t>
        lck(ContextMtx);

    llvm::LLVMContext *pContext = Context.get();
    if (!pContext) {
      auto NewContext = std::make_unique<llvm::LLVMContext>();
      pContext = NewContext.get();
      assert(pContext);
      Context = std::move(NewContext);
    }

    auto BinOrErr = llvm::object::createBinary(llvm::MemoryBufferRef(Data, ""),
                                               pContext, false);

    if (!BinOrErr)
      throw std::runtime_error("failed to create binary: " +
                               llvm::toString(BinOrErr.takeError()));
    TheBin = std::move(*BinOrErr);
  }

  llvm::object::Binary &Bin = *TheBin;

  bool Suitable = is_elf(Bin) || is_coff(Bin);
  if (!Suitable) {
    std::string Desc;

    if (auto *Obj = llvm::dyn_cast<llvm::object::ObjectFile>(&Bin)) {
      llvm::Triple TT = Obj->makeTriple();
      Desc = TT.str();
    } else {
      Desc = std::to_string(Bin.getType());
    }

    throw std::runtime_error("unexpected binary type (" + Desc + ")");
  }

  return std::move(TheBin);
}

}
}
