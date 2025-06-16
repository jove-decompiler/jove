#include "sret.h"

#include "llvm/IR/PassManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include "llvm/ADT/STLExtras.h" // for make_early_inc_range

using namespace llvm;

namespace jove {

void squashSRetFunctions(Module &M) {
  SmallVector<Function *, 8> Targets;
  for (Function &F : M) {
    if (!F.isDeclaration() && F.hasInternalLinkage() && !F.arg_empty() &&
        F.getArg(0)->hasStructRetAttr()) {
      Targets.push_back(&F);
    }
  }

  for (Function *OldF : Targets) {
    // Recover the struct return type
    Type *RetTy = OldF->getParamStructRetType(0);

    // Build new function type (skip sret arg)
    SmallVector<Type *, 8> ParamTys;
    for (auto It = std::next(OldF->arg_begin()); It != OldF->arg_end(); ++It)
      ParamTys.push_back(It->getType());
    FunctionType *NewFTy = FunctionType::get(RetTy, ParamTys, OldF->isVarArg());

    // Create new function and a dummy entry block for alloca
    Function *NewF = Function::Create(NewFTy, OldF->getLinkage(),
                                      OldF->getName() + ".squashed", &M);
    NewF->copyAttributesFrom(OldF);

    // Create a dummy entry block so we can allocate before cloning
    LLVMContext &Ctx = M.getContext();
    BasicBlock *DummyBB = BasicBlock::Create(Ctx, "sret.alloca", NewF);
    IRBuilder<> DummyBuilder(DummyBB);
    AllocaInst *RetAlloca = DummyBuilder.CreateAlloca(RetTy, nullptr, "retval");

    // Prepare value map: map old sret arg to RetAlloca
    ValueToValueMapTy VMap;
    VMap[&*OldF->arg_begin()] = RetAlloca;

    // Map remaining args
    auto OldArgIt = std::next(OldF->arg_begin());
    auto NewArgIt = NewF->arg_begin();
    for (; OldArgIt != OldF->arg_end(); ++OldArgIt, ++NewArgIt) {
      NewArgIt->setName(OldArgIt->getName());
      VMap[&*OldArgIt] = &*NewArgIt; // Correctly map oldArg -> newArg
    }

    // Clone the function body
    SmallVector<ReturnInst *, 8> Returns;
    CloneFunctionInto(NewF, OldF, VMap, CloneFunctionChangeType::GlobalChanges,
                      Returns);

    // Remove the dummy branch: link DummyBB to the real entry block (second
    // block in function)
    BasicBlock *ClonedEntry = nullptr;
    if (NewF->size() > 1) {
      auto It = NewF->begin();
      ++It; // skip DummyBB
      ClonedEntry = &*It;
    }
    if (ClonedEntry) {
      DummyBuilder.SetInsertPoint(DummyBB);
      DummyBuilder.CreateBr(ClonedEntry);
    }

    // Rewrite returns: load from alloca and return value
    for (ReturnInst *RI : Returns) {
      IRBuilder<> RetBuilder(RI);
      Value *Val = RetBuilder.CreateLoad(RetTy, RetAlloca);
      RetBuilder.CreateRet(Val);
      RI->eraseFromParent();
    }

    // Fix call sites safely
    SmallVector<CallInst *, 8> CallSites;
    for (User *U : OldF->users())
      if (CallInst *CI = dyn_cast<CallInst>(U))
        CallSites.push_back(CI);
    for (CallInst *CI : CallSites) {
      IRBuilder<> CB(CI);
      SmallVector<Value *, 8> Args;
      unsigned NumArgs = CI->arg_size();
      for (unsigned i = 1; i < NumArgs; ++i)
        Args.push_back(CI->getArgOperand(i));
      CallInst *NewCall = CB.CreateCall(NewF, Args);
      NewCall->setCallingConv(CI->getCallingConv());
      // Preserve metadata and debug location
      NewCall->setDebugLoc(CI->getDebugLoc());
      NewCall->copyMetadata(*CI);
      // Since old call was void (sret), there are no value uses to replace.
      CI->eraseFromParent();
    }

    OldF->eraseFromParent();
  }
}

} // namespace jove
