open Llvm

external struct_set_name : string -> lltype -> unit = "llvm_struct_set_name"
external does_gep_have_all_constant_indices : llvalue -> bool
  = "llvm_does_gep_have_all_constant_indices"
external gep_accumulate_constant_offset: llmodule -> llvalue -> int
  = "llvm_gep_accumulate_constant_offset"
external change_callees_to_fast_call : llvalue -> unit
  = "llvm_change_callees_to_fast_call"
external change_callees_to_c_call : llvalue -> unit
  = "llvm_change_callees_to_c_call"
external delete_function_body : llvalue -> unit = "llvm_delete_function_body"
external move_function_body : llvalue -> llvalue -> unit = "llvm_move_function_body"
external add_nonnull_param_attr : llvalue -> unit
  = "llvm_add_nonnull_param_attr"
external alias_begin : llmodule -> (llmodule, llvalue) llpos
  = "llvm_alias_begin"
external alias_succ : llvalue -> (llmodule, llvalue) llpos
  = "llvm_alias_succ"
external alias_end : llmodule -> (llmodule, llvalue) llrev_pos
  = "llvm_alias_end"
external alias_pred : llvalue -> (llmodule, llvalue) llrev_pos
  = "llvm_alias_pred"
external llvm_remove_function_attr : llvalue -> llattribute -> int -> unit
  = "llvm_remove_function_attr"

(* from llvm/bindings/ocaml/llvm/llvm.ml *)
let _AttrIndex_to_int index =
  match index with
  | AttrIndex.Function -> -1
  | AttrIndex.Return -> 0
  | AttrIndex.Param(n) -> 1 + n

let remove_function_attr f a i =
  llvm_remove_function_attr f a (_AttrIndex_to_int i)

let rec iter_alias_range f i e =
  if i = e then () else
    match i with
    | At_end _ -> raise (Invalid_argument "Invalid alias variable range.")
    | Before bb ->
      f bb;
      iter_alias_range f (alias_succ bb) e

let iter_aliases f m =
  iter_alias_range f (alias_begin m) (At_end m)
