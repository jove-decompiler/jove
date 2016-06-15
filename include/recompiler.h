#pragma once
#include <llvm/Object/ObjectFile.h>
#include <llvm/IR/Module.h>

namespace jove {

struct recompiler {
protected:
  const llvm::object::ObjectFile& O;
  llvm::Module& M;

public:
  recompiler(const llvm::object::ObjectFile&, llvm::Module&);

  virtual void recompile() const = 0;
};

}
