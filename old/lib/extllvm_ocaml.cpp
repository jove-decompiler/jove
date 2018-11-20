#include <llvm-c/Core.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/CallSite.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/DiagnosticInfo.h>
#include <llvm/IR/DiagnosticPrinter.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>

using namespace llvm;

extern "C" {
LLVMBool LLVMDoesGEPHaveAllConstantIndices(LLVMValueRef);
void LLVMRemoveInitializer(LLVMValueRef);
void LLVMSetStructName(LLVMTypeRef, const char *);
void LLVMDeleteFunctionBody(LLVMValueRef);
void LLVMMoveFunctionBody(LLVMValueRef, LLVMValueRef);
void LLVMChangeCalleesToFastCall(LLVMValueRef);
void LLVMChangeCalleesToCCall(LLVMValueRef);
void LLVMAddNonNullParamAttr(LLVMValueRef);
int LLVMGEPAccumulateConstantOffset(LLVMModuleRef, LLVMValueRef);
void LLVMRemoveAttributeAtIndex(LLVMValueRef F, LLVMAttributeIndex Idx,
                                LLVMAttributeRef A);
}

void LLVMRemoveInitializer(LLVMValueRef GlobalVar) {
  unwrap<GlobalVariable>(GlobalVar)->setInitializer(NULL);
}

void LLVMSetStructName(LLVMTypeRef Ty, const char *Name) {
  StructType *ST = cast<StructType>(unwrap(Ty));
  ST->setName(Name);
}

LLVMBool LLVMDoesGEPHaveAllConstantIndices(LLVMValueRef Inst) {
  return unwrap<GetElementPtrInst>(Inst)->hasAllConstantIndices();
}

int LLVMGEPAccumulateConstantOffset(LLVMModuleRef M, LLVMValueRef Inst) {
  const DataLayout& DL = unwrap(M)->getDataLayout();

  unsigned BitWidth =
      DL.getPointerTypeSizeInBits(unwrap<GetElementPtrInst>(Inst)->getType());
  APInt Offset(BitWidth, 0);

  if (!cast<GEPOperator>(unwrap<GetElementPtrInst>(Inst))
           ->accumulateConstantOffset(DL, Offset))
    return -1;

  return static_cast<int>(Offset.getZExtValue());
}

void LLVMRemoveAttributeAtIndex(LLVMValueRef F, LLVMAttributeIndex Idx,
                                LLVMAttributeRef A) {
  unwrap<Function>(F)->removeAttribute(Idx, unwrap(A).getKindAsEnum());
}

void LLVMDeleteFunctionBody(LLVMValueRef Fn) {
  unwrap<Function>(Fn)->deleteBody();
}

void LLVMMoveFunctionBody(LLVMValueRef Fn1, LLVMValueRef Fn2) {
  Function *DstFn = unwrap<Function>(Fn1);
  Function *SrcFn = unwrap<Function>(Fn2);
  DstFn->getBasicBlockList().splice(DstFn->begin(), SrcFn->getBasicBlockList());
}

static void ChangeCalleesToFastCall(Function *F) {
  for (User *U : F->users()) {
    if (isa<BlockAddress>(U))
      continue;
    CallSite CS(cast<Instruction>(U));
    CS.setCallingConv(CallingConv::Fast);
  }
}

static void ChangeCalleesToCCall(Function *F) {
  for (User *U : F->users()) {
    if (isa<BlockAddress>(U))
      continue;
    CallSite CS(cast<Instruction>(U));
    CS.setCallingConv(CallingConv::C);
  }
}

void LLVMChangeCalleesToFastCall(LLVMValueRef Fn) {
  ChangeCalleesToFastCall(unwrap<Function>(Fn));
}

void LLVMChangeCalleesToCCall(LLVMValueRef Fn) {
  ChangeCalleesToCCall(unwrap<Function>(Fn));
}

void LLVMAddNonNullParamAttr(LLVMValueRef Arg) {
  Argument *A = unwrap<Argument>(Arg);
  A->addAttr(AttributeSet::get(A->getContext(), A->getArgNo() + 1,
                               Attribute::NonNull));
}

extern "C" {
LLVMValueRef LLVMGetFirstAlias(LLVMModuleRef M);
LLVMValueRef LLVMGetLastAlias(LLVMModuleRef M);
LLVMValueRef LLVMGetNextAlias(LLVMValueRef GlobalAl);
LLVMValueRef LLVMGetPreviousAlias(LLVMValueRef GlobalAl);
LLVMModuleRef LLVMGetAliasParent(LLVMValueRef Alias);
}

LLVMValueRef LLVMGetFirstAlias(LLVMModuleRef M) {
  Module *Mod = unwrap(M);
  Module::alias_iterator I = Mod->alias_begin();
  if (I == Mod->alias_end())
    return nullptr;
  return wrap(&*I);
}

LLVMValueRef LLVMGetLastAlias(LLVMModuleRef M) {
  Module *Mod = unwrap(M);
  Module::alias_iterator I = Mod->alias_end();
  if (I == Mod->alias_begin())
    return nullptr;
  return wrap(&*--I);
}

LLVMValueRef LLVMGetNextAlias(LLVMValueRef GlobalAl) {
  GlobalAlias *GV = unwrap<GlobalAlias>(GlobalAl);
  Module::alias_iterator I(GV);
  if (++I == GV->getParent()->alias_end())
    return nullptr;
  return wrap(&*I);
}

LLVMValueRef LLVMGetPreviousAlias(LLVMValueRef GlobalAl) {
  GlobalAlias *GV = unwrap<GlobalAlias>(GlobalAl);
  Module::alias_iterator I(GV);
  if (I == GV->getParent()->alias_begin())
    return nullptr;
  return wrap(&*--I);
}

LLVMModuleRef LLVMGetAliasParent(LLVMValueRef Alias) {
  return wrap(unwrap<GlobalValue>(Alias)->getParent());
}
