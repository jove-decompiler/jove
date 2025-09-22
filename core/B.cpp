#include "B.h"
#include "triple.h"

#include <llvm/ADT/StringRef.h>
#include <llvm/IR/LLVMContext.h>

namespace jove {
namespace B {

std::unique_ptr<llvm::object::Binary> Create(llvm::StringRef Data) {
  static std::conditional_t<AreWeMT, std::mutex, std::monostate> ContextMtx;
  static std::unique_ptr<llvm::LLVMContext> Context;

  std::unique_ptr<llvm::object::Binary> TheBin;
  {
    std::conditional_t<AreWeMT, std::unique_lock<std::mutex>, nop_t>
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

  std::string Desc;
  const bool Suitable = is_elf(Bin) || is_coff(Bin);
  if (auto *Obj = llvm::dyn_cast<llvm::object::ObjectFile>(&Bin)) {
    if (Suitable && Obj->getArch() == TripleArchType)
      return std::move(TheBin);

    Desc = Obj->makeTriple().str();
  } else {
    Desc = "ID#" + std::to_string(Bin.getType());
  }

  std::string Msg = "unexpected binary type (" + Desc + ")";
  if (auto *Obj = llvm::dyn_cast<llvm::object::ObjectFile>(&Bin))
    Msg.append(", did you mean jove-" +
               std::string(TargetNameOfArchType(Obj->getArch())) + "?");

  throw std::runtime_error(Msg);
}

}
}
