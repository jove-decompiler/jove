open Llvm
open Extllvm

module Action = struct
  type t =
    | None
    | Rename_function
    | Replace_calls_with_ret
    | Extricate_call_operand
    | Only_external
    | Only_external_regex
    | Make_external_regex
    | Make_defined_globals_weak
    | Promote_call_operand_pointee_to_global
    | Change_fn_def_to_decl_regex
    | Make_fn_into_stub_regex
    | Delete_global_ctors
    | Remove_noinline_attr_regex
    | Set_global_constant_regex
    | Make_external_and_rename_regex
end

let main () =
  let ifp = ref "" in
  let ofp = ref "" in

  let a = ref Action.None in

  let args = ref [||] in

  Arg.parse
    [
      ("-i", Arg.Set_string ifp,
       "Specify input LLVM bitcode file");

      ("-o", Arg.Set_string ofp,
       "Specify output LLVM bitcode file");

      ("--rename-function", Arg.Unit (fun () -> a := Action.Rename_function),
       "Renames function");

      ("--replace-calls-with-return", Arg.Unit (fun () -> a := Action.Replace_calls_with_ret),
       "Replaces calls from to with return const_null");

      ("--extricate-call-operand", Arg.Unit (fun () -> a := Action.Extricate_call_operand),
       "Creates a global variable of the desired symbol, assigned to the operand prior to the given calls from to");

      ("--promote-call-operand-pointee-to-global", Arg.Unit (fun () -> a := Action.Promote_call_operand_pointee_to_global),
       "Creates a global variable of the desired symbol, of the pointee type to the given operand prior to the given calls from to");

      ("--only-external", Arg.Unit (fun () -> a := Action.Only_external),
       "Sets linkage of all globals to internal except for the provided list, which are made external");

      ("--only-external-regex", Arg.Unit (fun () -> a := Action.Only_external_regex),
       "Sets linkage of all globals to internal except for those matching regex");

      ("--make-external-regex", Arg.Unit (fun () -> a := Action.Make_external_regex),
       "Sets linkage of all globals matching regex to external");

      ("--remove-noinline-attr-regex", Arg.Unit (fun () -> a := Action.Remove_noinline_attr_regex),
       "Removes the noinline attribute on all functions matching the regex");

      ("--set-global-constant-regex", Arg.Unit (fun () -> a := Action.Set_global_constant_regex),
       "Sets globals to be constant on all globals matching the regex");

      ("--change-fn-def-to-decl-regex", Arg.Unit (fun () -> a := Action.Change_fn_def_to_decl_regex),
       "Turns function definitions into declarations");

      ("--make-fn-into-stub-regex", Arg.Unit (fun () -> a := Action.Make_fn_into_stub_regex),
       "Replaces function definitions with empty stubs that return 0 or void");

      ("--delete-global-ctors", Arg.Unit (fun () -> a := Action.Delete_global_ctors),
       "Deletes all global ctors");

      ("--make-external-and-rename-regex", Arg.Unit (fun () -> a := Action.Make_external_and_rename_regex),
       "Makes functions matching regex to be external linkage and rename to be prefixed by source file's base name");

      ("--make-defined-globals-weak", Arg.Unit (fun () -> a := Action.Make_defined_globals_weak),
       "Sets linkage of all defined globals to be weak")
    ]
    (fun anonarg -> args := Array.append !args [|anonarg|])
    "usage: llknife -i input -o output [--rename-function before after] [--replace-calls-with-return caller callee] [--extricate-call-operand caller callee operand_index new_global_symbol] [--only-external symbol symbol ...]";

  (*
   * validate arguments
   *)
  if !ifp = "" || not (Sys.file_exists !ifp) then
    assert false;

  if !ofp = "" then
    ofp := !ifp;

  if !a <> Action.Only_external (* variable number of arguments *) then
    assert (Array.length !args = (
        match !a with
        | Action.Rename_function -> 2
        | Action.Replace_calls_with_ret -> 2
        | Action.Extricate_call_operand -> 4
        | Action.Make_defined_globals_weak -> 0
        | Action.Delete_global_ctors -> 0
        | Action.Make_external_and_rename_regex -> 1
        | Action.Make_external_regex -> 1
        | Action.Remove_noinline_attr_regex -> 1
        | Action.Set_global_constant_regex -> 1
        | Action.Only_external_regex -> 1
        | Action.Change_fn_def_to_decl_regex -> 1
        | Action.Make_fn_into_stub_regex -> 1
        | Action.Promote_call_operand_pointee_to_global -> 4
        | _ -> -1
      )
    );

  (*
   * LLVM initialization
   *)
  let llctx = create_context () in

  (*
   * parse input
   *)
  let llm =
    try
      Llvm_bitreader.parse_bitcode llctx (MemoryBuffer.of_file !ifp)
    with _ ->
      exit 0
  in

  (*
   * helpful functions
   *)
  let get x = match x with | None -> assert false | Some x' -> x' in
  let llvm_function_of_symbol sym = get (lookup_function sym llm) in
  let sscan = Scanf.sscanf in
  let id = fun x -> x in
  let beginswith s' s =
    let sl = String.length s in
    let s'l = String.length s' in
    sl >= s'l && s' = (String.sub s 0 s'l)
  in
  let spr = Printf.sprintf in
  let llvm_globals llm = fold_left_globals (fun res llg -> llg::res) [] llm in
  let llvm_functions llm = fold_left_functions (fun res llf -> llf::res) [] llm in

  (*
   * execute requested action
   *)
  (match !a with
   | Action.None -> ()

   | Action.Rename_function ->
     set_value_name (!args).(1) (llvm_function_of_symbol (!args).(0))

   | Action.Replace_calls_with_ret ->
     let caller = llvm_function_of_symbol (!args).(0) in
     let callee = llvm_function_of_symbol (!args).(1) in

     let calls =
       fold_left_uses (fun res llu ->
           let instr = user llu in
           if classify_value instr = ValueKind.Instruction Opcode.Call &&
              (block_parent (instr_parent instr)) = caller then
             instr::res
           else
             res
         ) [] callee
     in

     List.iter (fun call ->
         replace_all_uses_with call (undef (type_of call));

         let term' = block_terminator (instr_parent call) in
         match term' with
         | Some term ->
           let b = builder_before llctx term in
           let caller_ty = element_type (type_of caller) in
           let ret_ty = return_type caller_ty in

           if ret_ty = (void_type llctx) then
             ignore (build_ret_void b)
           else
             ignore (build_ret (const_null ret_ty) b);

           (* deleting the terminator could change whether the function is noreturn *)
           remove_function_attr caller Attribute.Noreturn;
           delete_instruction term
         | _ -> ();
       ) calls;

     List.iter delete_instruction calls;

   | Action.Extricate_call_operand ->
     let caller = llvm_function_of_symbol (!args).(0) in
     let callee = llvm_function_of_symbol (!args).(1) in
     let opidx  = sscan (!args).(2) "%d" id in
     let gvsym  = (!args).(3) in

     (* get type for new global *)
     let callee_ty = element_type (type_of callee) in
     let gvty = (param_types callee_ty).(opidx) in

     (* create global *)
     let gv = define_global gvsym (const_null gvty) llm in
     set_linkage Linkage.External gv;

     (* get list of calls from given caller *)
     let calls =
       fold_left_uses (fun res llu ->
           let instr = user llu in
           if classify_value instr = ValueKind.Instruction Opcode.Call &&
              (block_parent (instr_parent instr)) = caller then
             instr::res
           else
             res
         ) [] callee
     in

     (* assign operands to global *)
     List.iter (fun call ->
         let b = builder_before llctx call in
         ignore (build_store (operand call opidx) gv b)
       ) calls;

   | Action.Only_external ->
     iter_globals (fun llgl ->
         if not (is_declaration llgl) && not (beginswith "llvm." (value_name llgl)) then
           set_linkage Linkage.Internal llgl
       ) llm;
     iter_functions (fun llf ->
         if not (is_declaration llf) && not (is_intrinsic llf) then
           set_linkage Linkage.Internal llf
       ) llm;

     let llfs' = Array.map (fun sym -> lookup_function sym llm) !args in
     let llgs' = Array.map (fun sym -> lookup_global sym llm) !args in

     let llfs = List.filter (fun llf' -> llf' <> None) (Array.to_list llfs') in
     let llgs = List.filter (fun llg' -> llg' <> None) (Array.to_list llgs') in

     List.iter
       (set_linkage Linkage.External)
       (List.map get (llfs@llgs))

   | Action.Change_fn_def_to_decl_regex ->
     let r = Str.regexp (!args).(0) in
     iter_functions (fun llf ->
         if Str.string_match r (value_name llf) 0 &&
            Array.length (basic_blocks llf) != 0 then
           delete_function_body llf
       ) llm

   | Action.Make_fn_into_stub_regex ->
     let r = Str.regexp (!args).(0) in
     iter_functions (fun llf ->
         if Str.string_match r (value_name llf) 0 &&
            Array.length (basic_blocks llf) != 0 then (
           delete_function_body llf;

           let bb = append_block llctx "stub" llf in

           let b = builder_at_end llctx bb in

           let llf_ty = element_type (type_of llf) in
           let ret_ty = return_type llf_ty in

           if ret_ty = (void_type llctx) then
             ignore (build_ret_void b)
           else
             ignore (build_ret (const_null ret_ty) b);

           remove_function_attr llf Attribute.Noreturn
         )
       ) llm

   | Action.Make_external_regex ->
     let r = Str.regexp (!args).(0) in
     iter_globals (fun llgl ->
         if Str.string_match r (value_name llgl) 0 then
           set_linkage Linkage.External llgl
       ) llm;
     iter_functions (fun llf ->
         if Str.string_match r (value_name llf) 0 then
           set_linkage Linkage.External llf
       ) llm

   | Action.Remove_noinline_attr_regex ->
     let r = Str.regexp (!args).(0) in
     iter_functions (fun llf ->
         if Str.string_match r (value_name llf) 0 then
           remove_function_attr llf Attribute.Noinline
       ) llm

   | Action.Set_global_constant_regex ->
     let r = Str.regexp (!args).(0) in
     iter_globals (fun llg ->
         if Str.string_match r (value_name llg) 0 then
           set_global_constant true llg
       ) llm

   | Action.Only_external_regex ->
     let r = Str.regexp (!args).(0) in

     iter_functions (fun llf ->
         if not (is_declaration llf) &&
            not (is_intrinsic llf) &&
            not (Str.string_match r (value_name llf) 0) then
           set_linkage Linkage.Internal llf
       ) llm;
     iter_globals (fun llgl ->
         if not (is_declaration llgl) &&
            not (beginswith "llvm." (value_name llgl)) &&
            not (Str.string_match r (value_name llgl) 0) then
           set_linkage Linkage.Internal llgl
       ) llm;
     iter_aliases (fun lla ->
         if not (Str.string_match r (value_name lla) 0) then
           set_linkage Linkage.Internal lla
       ) llm;

   | Action.Make_defined_globals_weak ->
     iter_globals (fun llgl ->
         if not (is_declaration llgl) && not (beginswith "llvm." (value_name llgl)) then
           set_linkage Linkage.Weak llgl
       ) llm;
     iter_functions (fun llf ->
         if not (is_declaration llf) then
           set_linkage Linkage.Weak llf
       ) llm

   | Action.Delete_global_ctors ->
     let ctrs_gl' = lookup_global "llvm.global_ctors" llm in
     if ctrs_gl' <> None then
       delete_global (get ctrs_gl')

   | Action.Make_external_and_rename_regex ->
     let prefix = Filename.chop_extension (Filename.basename !ifp) in
     let r = Str.regexp (!args).(0) in
     iter_functions (fun llf ->
         if Str.string_match r (value_name llf) 0 then (
           set_linkage Linkage.External llf;
           set_value_name (spr "%s_%s" prefix (value_name llf)) llf
         )
       ) llm

   | Action.Promote_call_operand_pointee_to_global ->
     let caller = llvm_function_of_symbol (!args).(0) in
     let callee = llvm_function_of_symbol (!args).(1) in
     let opidx  = sscan (!args).(2) "%d" id in
     let gvsym  = (!args).(3) in

     (* get type for new global *)
     let callee_ty = element_type (type_of callee) in
     let gvty = element_type (param_types callee_ty).(opidx) in

     (* create global *)
     let gv = define_global gvsym (const_null gvty) llm in
     set_linkage Linkage.External gv;

     (* get list of calls from given caller *)
     let calls =
       fold_left_uses (fun res llu ->
           let instr = user llu in
           if classify_value instr = ValueKind.Instruction Opcode.Call &&
              (block_parent (instr_parent instr)) = caller then
             instr::res
           else
             res
         ) [] callee
     in

     assert (calls <> []);
     let lcl = operand (List.hd calls) opidx in
     replace_all_uses_with lcl gv;

     let casts =
       fold_left_uses (fun res llu ->
           let instr = user llu in
           if classify_value instr = ValueKind.Instruction Opcode.BitCast then
             instr::res
           else
             res
         ) [] gv in

     let lifetimecalls =
       List.fold_left (fun res' cast ->
           res' @ (fold_left_uses (fun res llu ->
               let instr = user llu in
               if classify_value instr = ValueKind.Instruction Opcode.Call &&
                  beginswith "llvm.lifetime." (value_name (operand instr ((num_operands instr) - 1))) then
                 instr::res
               else
                 res
             ) [] cast)
         ) [] casts in
     List.iter delete_instruction lifetimecalls
  );

  (*
   * verify result
   *)
  let err' = Llvm_analysis.verify_module llm in
  match err' with
  | Some err -> print_endline err
  | _ -> ();

  (*
   * write result
   *)
    assert (Llvm_bitwriter.write_bitcode_file llm !ofp);

  (*
   * LLVM clean-up
   *)
    dispose_module llm;
    dispose_context llctx;
;;

main ()
