#include <llvm-c/Core.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/callback.h>
#include <caml/bigarray.h>

LLVMBool LLVMDoesGEPHaveAllConstantIndices(LLVMValueRef Inst);
void LLVMRemoveInitializer(LLVMValueRef GlobalVar);
void LLVMSetStructName(LLVMTypeRef Ty, const char *Name);
LLVMBool LLVMDoesGEPHaveAllConstantIndices(LLVMValueRef Inst);
void LLVMDeleteFunctionBody(LLVMValueRef Fn);
void LLVMMoveFunctionBody(LLVMValueRef Fn1, LLVMValueRef Fn2);
void LLVMChangeCalleesToFastCall(LLVMValueRef Fn);
void LLVMChangeCalleesToCCall(LLVMValueRef Fn);
void LLVMAddNonNullParamAttr(LLVMValueRef);
int LLVMGEPAccumulateConstantOffset(LLVMModuleRef, LLVMValueRef);
void LLVMRemoveAttributeAtIndex(LLVMValueRef F, LLVMAttributeIndex Idx,
                                LLVMAttributeRef A);

/* string -> lltype -> unit */
CAMLprim value llvm_struct_set_name(value Name, LLVMTypeRef Ty) {
  LLVMSetStructName(Ty, String_val(Name));
  return Val_unit;
}

/* llvalue -> bool */
CAMLprim value llvm_does_gep_have_all_constant_indices(LLVMValueRef Val) {
  return Val_bool(LLVMDoesGEPHaveAllConstantIndices(Val));
}

/* llmodule -> llvalue -> int */
CAMLprim value llvm_gep_accumulate_constant_offset(LLVMModuleRef M,
                                                   LLVMValueRef V) {
  return Val_int(LLVMGEPAccumulateConstantOffset(M, V));
}

/* llvalue -> unit */
CAMLprim value llvm_delete_function_body(LLVMValueRef Fn) {
  LLVMDeleteFunctionBody(Fn);
  return Val_unit;
}

/* llvalue -> llvalue -> unit */
CAMLprim value llvm_move_function_body(LLVMValueRef Fn1, LLVMValueRef Fn2) {
  LLVMMoveFunctionBody(Fn1, Fn2);
  return Val_unit;
}

/* llvalue -> unit */
CAMLprim value llvm_change_callees_to_fast_call(LLVMValueRef Fn) {
  LLVMChangeCalleesToFastCall(Fn);
  return Val_unit;
}

/* llvalue -> unit */
CAMLprim value llvm_change_callees_to_c_call(LLVMValueRef Fn) {
  LLVMChangeCalleesToCCall(Fn);
  return Val_unit;
}

/* llvalue -> unit */
CAMLprim value llvm_add_nonnull_param_attr(LLVMValueRef Arg) {
  LLVMAddNonNullParamAttr(Arg);
  return Val_unit;
}

/* llvalue -> llattribute -> int -> unit */
CAMLprim value llvm_remove_function_attr(LLVMValueRef F, LLVMAttributeRef A,
                                         value Index) {
  LLVMRemoveAttributeAtIndex(F, Int_val(Index), A);
  return Val_unit;
}

LLVMValueRef LLVMGetFirstAlias(LLVMModuleRef M);
LLVMValueRef LLVMGetLastAlias(LLVMModuleRef M);
LLVMValueRef LLVMGetNextAlias(LLVMValueRef GlobalAl);
LLVMValueRef LLVMGetPreviousAlias(LLVMValueRef GlobalAl);
LLVMModuleRef LLVMGetAliasParent(LLVMValueRef Alias);

static value alloc_variant(int tag, void *Value) {
  value Iter = alloc_small(1, tag);
  Field(Iter, 0) = Val_op(Value);
  return Iter;
}

#define DEFINE_ITERATORS(camlname, cname, pty, cty, pfun)                      \
  /* llmodule -> ('a, 'b) llpos */                                             \
  CAMLprim value llvm_##camlname##_begin(pty Mom) {                            \
    cty First = LLVMGetFirst##cname(Mom);                                      \
    if (First)                                                                 \
      return alloc_variant(1, First);                                          \
    return alloc_variant(0, Mom);                                              \
  }                                                                            \
                                                                               \
  /* llvalue -> ('a, 'b) llpos */                                              \
  CAMLprim value llvm_##camlname##_succ(cty Kid) {                             \
    cty Next = LLVMGetNext##cname(Kid);                                        \
    if (Next)                                                                  \
      return alloc_variant(1, Next);                                           \
    return alloc_variant(0, pfun(Kid));                                        \
  }                                                                            \
                                                                               \
  /* llmodule -> ('a, 'b) llrev_pos */                                         \
  CAMLprim value llvm_##camlname##_end(pty Mom) {                              \
    cty Last = LLVMGetLast##cname(Mom);                                        \
    if (Last)                                                                  \
      return alloc_variant(1, Last);                                           \
    return alloc_variant(0, Mom);                                              \
  }                                                                            \
                                                                               \
  /* llvalue -> ('a, 'b) llrev_pos */                                          \
  CAMLprim value llvm_##camlname##_pred(cty Kid) {                             \
    cty Prev = LLVMGetPrevious##cname(Kid);                                    \
    if (Prev)                                                                  \
      return alloc_variant(1, Prev);                                           \
    return alloc_variant(0, pfun(Kid));                                        \
  }

DEFINE_ITERATORS(alias, Alias, LLVMModuleRef, LLVMValueRef,
                 LLVMGetAliasParent)
