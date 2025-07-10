#include "byval.h"

// Remove 'byval' parameters by cloning functions and rewriting call sites.
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/ADT/STLExtras.h"

using namespace llvm;

namespace jove {

void squashByvalFunctions(Module &M) {
  const DataLayout &DL = M.getDataLayout();
  std::vector<Function *> ToRewrite;

  LLVMContext &Ctx = M.getContext();

  for (Function &F : M) {
    if (F.isDeclaration() || !F.hasInternalLinkage())
      continue;

    // Iterate through parameters to find 'byval' attributes
    // Parameter attributes are 1-based indices, so F.hasParamAttribute(i + 1, ...)
    for (unsigned i = 0; i < F.getFunctionType()->getNumParams(); ++i) {
      if (F.hasParamAttribute(i, Attribute::ByVal)) {
        Type *ValTy = F.getParamByValType(i);
        assert(ValTy);

        llvm::errs() << llvm::formatv("{0} byval param #{1}: {2}\n",
                                      F.getName(), i, *ValTy);
        ToRewrite.push_back(&F);
        break; // Found one, no need to check other parameters of this function
      }
    }
  }

  for (Function *F : ToRewrite) {
    for (User *U : F->users()) {
      auto *CI = dyn_cast<CallInst>(U);
      if (!CI)
        continue;

      IRBuilder<> B(CI);
      std::vector<Value *> Args;
      for (unsigned i = 0; i < CI->arg_size(); ++i) {
        if (CI->paramHasAttr(i, Attribute::ByVal)) {
          Type *ValTy = CI->getParamByValType(i);
          assert(ValTy);

          CI->removeAttributeAtIndex(i+1, llvm::Attribute::ByVal);

          AllocaInst *Tmp = B.CreateAlloca(ValTy, nullptr, "byval.tmp");

          Align A = DL.getABITypeAlign(ValTy);
          uint64_t Sz = DL.getTypeAllocSize(ValTy);

          B.CreateMemCpyInline(Tmp, A, CI->getArgOperand(i), A, B.getInt32(Sz));

          CI->setOperand(i, Tmp);
        }
      }
    }

    for (auto &arg : F->args()) {
      if (arg.hasByValAttr())
        arg.removeAttr(llvm::Attribute::ByVal);
    }
  }
}

}
