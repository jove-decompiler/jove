open Llvm
open Graph

(*
 * helpful functions
 *)
let sscan = Scanf.sscanf
let id = fun x -> x
let beginswith s' s =
  let sl = String.length s in
  let s'l = String.length s' in
  sl >= s'l && s' = (String.sub s 0 s'l)
let spr = Printf.sprintf
let llvm_globals llm = fold_left_globals (fun res llg -> llg::res) [] llm
let llvm_functions llm = fold_left_functions (fun res llf -> llf::res) [] llm
let numbered l = List.mapi (fun i elem -> (i, elem)) l
let pe = print_endline
let fst4 (x, _, _, _) = x
let snd4 (_, x, _, _) = x
let thd4 (_, _, x, _) = x
let fth4 (_, _, _, x) = x

let rec range i j = if i >= j then [] else i :: (range (i+1) j)
let tuple_of_list3 l = (List.nth l 0, List.nth l 1, List.nth l 2)

(* split a list of length n divisible by k into a list of lists with all length
 * k. precondition: n % k = 0 *)
let rec split n xs =
  let rec take k xs ys = match k, xs with
    | 0, _ -> List.rev ys :: split n xs
    | _, [] -> if ys = [] then [] else [ys]
    | _, x::xs' -> take (k - 1) xs' (x::ys)
  in take n xs []

let fold_left_defined_functions f init llm =
  fold_left_functions (fun res llf ->
    if not (is_declaration llf) then (
      f res llf
    ) else res
  ) init llm

let defined_functions llm =
  fold_left_defined_functions (fun res llf -> llf::res) [] llm

let uses_of llv = fold_left_uses (fun res u -> u::res) [] llv
let users_of llv = List.map user (uses_of llv)
let iter_users f llv = List.iter f (users_of llv)

let function_head_instruction llf =
  (match instr_begin (entry_block llf) with Before (i) -> i | _ -> assert false)

let return_instructions llf = fold_left_blocks
  (fun res llbb ->
    let bt_o = block_terminator llbb in
    if bt_o <> None &&
       instr_opcode (BatOption.get bt_o) = Opcode.Ret then
      (BatOption.get bt_o)::res
    else
      res) [] llf

let builder_after llctx i =
  let b = builder llctx in
  position_builder (instr_succ i) b;
  b

(* precondition: llf is never used as a callback *)
let change_function_parameters llm llf param_tys param_idx_mapping =
  (* verify precondition *)
  assert (List.for_all (fun u ->
      classify_value u = ValueKind.Instruction Opcode.Call &&
      operand u ((num_operands u) - 1) = llf
    ) (users_of llf));

  (* take name of old definition *)
  let name = value_name llf in
  set_value_name "" llf;

  (* make new function definition *)
  let llf_ty = element_type (type_of llf) in
  let llf_ret_ty = return_type llf_ty in
  let llf' = define_function name
      (if is_var_arg llf_ty
       then var_arg_function_type llf_ret_ty param_tys
       else function_type llf_ret_ty param_tys)
      llm in

  (* preserve attributes *)
  List.iter (add_function_attr llf') (function_attr llf);

  (* preserve linkage of old definition *)
  set_linkage (linkage llf) llf';

  (* take body of old definition *)
  remove_block (entry_block llf');
  move_function_body llf' llf;

  (* old definition is now declaration, so must be declared external *)
  set_linkage Linkage.External llf;

  (* replace uses of parameters from old definition *)
  List.iter (fun (i, p) ->
      let p' = (params llf').(param_idx_mapping.(i)) in
      replace_all_uses_with p p'
    ) (List.filter
         (fun (i, _) -> param_idx_mapping.(i) >= 0)
         (numbered (Array.to_list (params llf))));

  (* preserve original parameter names *)
  List.iter (fun (i, p) ->
      let p' = (params llf').(param_idx_mapping.(i)) in
      set_value_name (value_name p) p'
    ) (List.filter
         (fun (i, _) -> param_idx_mapping.(i) >= 0)
         (numbered (Array.to_list (params llf))));

  (* preserve original parameter attributes *)
  List.iter (fun (i, p) ->
      let p' = (params llf').(param_idx_mapping.(i)) in
      List.iter (add_param_attr p') (param_attr p)
    ) (List.filter
         (fun (i, _) -> param_idx_mapping.(i) >= 0)
         (numbered (Array.to_list (params llf))));

  (* replace old calls with calls using new definition *)
  List.iter (fun call ->
      (* set new operands to undef *)
      let operands' = Array.map undef param_tys in

      (* fill new operands with old passed operands *)
      List.iter (fun (i, p) ->
          let i' = param_idx_mapping.(i) in
          operands'.(i') <- operand call i
        ) (List.filter
             (fun (i, _) -> param_idx_mapping.(i) >= 0)
             (numbered (Array.to_list (params llf))));

      (* build new call *)
      let b = builder_before (module_context llm) call in
      let call' = build_call llf' operands' "" b in

      (* replace uses of old call with new call if old call did not return void *)
      if type_of call <> (void_type (module_context llm)) then
        replace_all_uses_with call call';

      (* delete the old call *)
      delete_instruction call
    ) (users_of llf);

  delete_function llf;
  llf'

(* precondition: llf is never used as a callback *)
let change_function_return llm llf ret_ty fix_return_value_uses =
  (* verify precondition *)
  assert (List.for_all (fun u ->
      classify_value u = ValueKind.Instruction Opcode.Call &&
      operand u ((num_operands u) - 1) = llf
    ) (users_of llf));

  (* take name of old definition *)
  let name = value_name llf in
  set_value_name "" llf;

  (* make new function definition *)
  let llf_ty = element_type (type_of llf) in
  let llf_param_tys = param_types llf_ty in
  let llf' = define_function name
                             (if is_var_arg llf_ty
                              then var_arg_function_type ret_ty llf_param_tys
                              else function_type ret_ty llf_param_tys)
                             llm in

  (* preserve attributes *)
  List.iter (add_function_attr llf') (function_attr llf);
  List.iter2 (fun arg arg' -> List.iter (add_param_attr arg') (param_attr arg))
    (Array.to_list (params llf))
    (Array.to_list (params llf'));

  (* preserve linkage of old definition *)
  set_linkage (linkage llf) llf';

  (* take body of old definition *)
  remove_block (entry_block llf');
  move_function_body llf' llf;

  (* old definition is now declaration, so must be declared external *)
  set_linkage Linkage.External llf;

  (* replace uses of parameters from old definition *)
  Array.iteri (fun i p ->
    let p' = (params llf').(i) in
    replace_all_uses_with p p'
  ) (params llf);

  (* preserve original parameter names *)
  Array.iteri (fun i p ->
    let p' = (params llf').(i) in
    set_value_name (value_name p) p'
  ) (params llf);

  (* replace old calls with calls using new definition *)
  List.iter (fun call ->
    (* get operands *)
    let operands' = Array.init (Array.length (params llf))
                               (fun i -> operand call i) in

    (* build new call *)
    let b = builder_before (module_context llm) call in
    let call' = build_call llf' operands' "" b in

    (* replace uses of old call with new call if old call did not return void *)
    if type_of call <> (void_type (module_context llm)) then
      fix_return_value_uses b call call';

    (* delete the old call *)
    assert (List.length (users_of call) = 0);
    delete_instruction call
  ) (users_of llf);

  delete_function llf;
  llf'

(* precondition: llf is never used as a callback *)
let delete_unused_function_parameters llm llf =
  let p = params llf in
  let uidxs = List.filter
      (fun i -> List.length (uses_of p.(i)) <> 0)
      (range 0 (Array.length p)) in

  let pmap = Array.make (Array.length p) (-1) in
  List.iteri (fun i' i -> pmap.(i) <- i') uidxs;

  let ptys' =
    Array.of_list (
      List.map type_of (
        List.filter (fun arg ->
            List.length (uses_of arg) <> 0)
          (Array.to_list p))) in

  change_function_parameters llm llf ptys' pmap

module IntMap = Map.Make(struct type t = int let compare = compare end)

module LLSet = Set.Make(struct type t = llvalue let compare = Pervasives.compare end)
module LLMap = Map.Make(struct type t = llvalue let compare = Pervasives.compare end)

module LLFunction =
struct
  type t = llvalue

  let hash = Hashtbl.hash
  let compare = Pervasives.compare
  let equal f1 f2 = (compare f1 f2 = 0)
end

module LLCallGraph =
struct
  type t = LLSet.t LLMap.t

  module V = LLFunction

  let of_module llm =
    let init = fold_left_defined_functions (fun res llf ->
        LLMap.add llf LLSet.empty res
      ) LLMap.empty llm in

    fold_left_defined_functions (fun res llf ->
        fold_left_uses (fun res' llu ->
          let ins = user llu in
          if classify_value ins = ValueKind.Instruction Opcode.Call &&
             (operand ins ((num_operands ins) - 1)) = llf then (
            let caller = block_parent (instr_parent ins) in
            let callee = llf in
            LLMap.add caller (LLSet.add callee (LLMap.find caller res')) res'
          ) else (
            res'
          )
        ) res llf
      ) init llm

  let verts cg = List.map fst (LLMap.bindings cg)

  let iter_vertex f cg = List.iter f (verts cg)
  let iter_succ f cg llf = LLSet.iter f (LLMap.find llf cg)
  let succ cg llf = LLMap.find llf cg
end

module LLCallGraphSCC = Components.Make(LLCallGraph)
module LLCallGraphTopological = Topological.Make(LLCallGraph)
module LLCallGraphPathChecker = Path.Check(LLCallGraph)

module TCGGlobalType =
struct
  type t =
  | I32
  | I64
  | COUNT (* XXX should not appear *)
end

module TCGGlobal =
struct
  type t = lltype * int * int * string

  let ty = fst4
  let idx = snd4
  let offset = thd4
  let name = fth4

  let hash tcggbl =
    Hashtbl.hash (idx tcggbl)

  let compare tcggbl1 tcggbl2 =
    Pervasives.compare (idx tcggbl1) (idx tcggbl2)

  let equal tcggbl1 tcggbl2 =
    idx tcggbl1 = idx tcggbl2
end

module TCGGlobalMap = Map.Make(TCGGlobal)

module HelperMetadata =
struct
  type t =
    | Inputs
    | Outputs

  let to_int hmd = match hmd with
    | Inputs -> 0
    | Outputs -> 1

  let add llctx llm llf hmd mdn =
    add_named_metadata_operand
      llm
      (value_name llf)
      (mdnode
         llctx
         (Array.append [|const_int (i8_type llctx) (to_int hmd)|] mdn))

  let add_input llf idx =
    let llm = global_parent llf in
    let llctx = module_context llm in
    add llctx llm llf Inputs [|const_int (i32_type llctx) idx|]

  let add_output llf idx =
    let llm = global_parent llf in
    let llctx = module_context llm in
    add llctx llm llf Outputs [|const_int (i32_type llctx) idx|]
end

let main () =
  let ifp = ref "" in
  let ofp = ref "" in
  let arch_s = ref "" in
  let args = ref [] in

  Arg.parse
    [
      ("-i", Arg.Set_string ifp,
       "Specify input LLVM bitcode file");

      ("-o", Arg.Set_string ofp,
       "Specify output LLVM bitcode file");

      ("--arch", Arg.Set_string arch_s,
       "Specify architecture (i386 x86_64 arm aarch64 mipsel)")
    ]
    (fun anonarg -> args := anonarg :: !args)
    "usage: transform-helpers -i helpers -o helpers [globals [globals...]]";

  args := List.rev !args;

  (*
   * LLVM initialization
   *)
  let llctx = create_context () in

  (*
   * validate & parse arguments
   *)
  if !ifp = "" || not (Sys.file_exists !ifp) || !ofp = "" then
    assert false;

  let tcgglbll = List.mapi (fun idx (ty_s, off_s, nm) ->
      let ty =
        match ty_s with
        | "I32" -> i32_type llctx
        | "I64" -> i64_type llctx
        | _ -> assert false
      in
      let off = sscan off_s "%d" id in
      (ty, idx + 1, off, nm)
    ) (List.map tuple_of_list3 (split 3 !args)) in

  (*
   * parse input
   *)
  let llm = Llvm_bitreader.parse_bitcode llctx (MemoryBuffer.of_file !ifp) in

  (*
   * get CPUState type
   *)
  let cpusttynm =
    match !arch_s with
    | "i386"
    | "x86_64" -> "struct.CPUX86State"
    | "arm"
    | "aarch64" -> "struct.CPUARMState"
    | "mipsel" -> "struct.CPUMIPSState"
    | _ -> assert false
  in
  let cpustty = BatOption.get (type_by_name llm cpusttynm) in
  let cpustptrty = pointer_type cpustty in

  (*
   * create shadow stack
   *)
  let shadowstack_len = 8192 * 1024 in (* 8192 KiB *)
  let shadowstack_ty = array_type (i8_type llctx) shadowstack_len in

  let shadowstack = declare_global
      shadowstack_ty
      "shadow_stack"
      llm in
  set_initializer (const_null shadowstack_ty) shadowstack;
  set_linkage Linkage.Internal shadowstack;
  set_thread_local true shadowstack;

  (*
   * create CPUState (thread-local) global variable. the stack pointer will be
   * initialized to the shadow stack (this is architecture dependent)
   *)
  assert (classify_type cpustty = TypeKind.Struct);
  let cpustelemtys = struct_element_types cpustty in
  let cpustinit = Array.init
      (Array.length cpustelemtys)
      (fun idx -> const_null cpustelemtys.(idx)) in

  (match !arch_s with
  | "i386"
  | "x86_64" ->
    let regsty = cpustelemtys.(0) in
    assert (classify_type regsty = TypeKind.Array);

    let regs = Array.make
        (array_length regsty)
        (const_null (element_type regsty)) in
    (*
     * #define R_ESP 4
     * #define R_EBP 5
     *)
    let top_of_stack =
      const_ptrtoint
        (const_gep shadowstack
           [|const_int (i32_type llctx) 0;
             const_int (i32_type llctx) (shadowstack_len - 1024)|])
        (element_type regsty) in
    regs.(4) <- top_of_stack;
    regs.(5) <- top_of_stack;
    cpustinit.(0) <- const_array (element_type regsty) regs
  | "arm" ->
    let regsty = cpustelemtys.(0) in
    assert (classify_type regsty = TypeKind.Array);

    let regs = Array.make
        (array_length regsty)
        (const_null (element_type regsty)) in
    (*
     * R13 is used as the stack pointer
     *)
    let top_of_stack =
      const_ptrtoint
        (const_gep shadowstack
           [|const_int (i32_type llctx) 0;
             const_int (i32_type llctx) (shadowstack_len - 1024)|])
        (element_type regsty) in
    regs.(13) <- top_of_stack;
    cpustinit.(0) <- const_array (element_type regsty) regs
  | "aarch64" ->
    let regsty = cpustelemtys.(1) in
    assert (classify_type regsty = TypeKind.Array);

    let regs = Array.make
        (array_length regsty)
        (const_null (element_type regsty)) in
    (*
     * x31 is used as the stack pointer
     *)
    let top_of_stack =
      const_ptrtoint
        (const_gep shadowstack
           [|const_int (i32_type llctx) 0;
             const_int (i32_type llctx) (shadowstack_len - 1024)|])
        (element_type regsty) in
    regs.(31) <- top_of_stack;
    cpustinit.(1) <- const_array (element_type regsty) regs
  | "mipsel" -> ()
  | _ -> assert false);

  let glblcpust = declare_global
      cpustty
      "cpu_state"
      llm in
  set_initializer (const_named_struct cpustty cpustinit) glblcpust;
  set_linkage Linkage.External glblcpust;
  set_thread_local true glblcpust;

  (*
   * build map from functions to CPUState parameters
   *)
  let has_cpu_state_parameter llf =
    List.exists
      (fun llty -> llty = cpustptrty)
      (Array.to_list (param_types (element_type (type_of llf))))
  in
  let cpu_state_parameter_index llf =
    fst
      (List.hd
         (List.filter
            (fun (_, llty) -> llty = cpustptrty)
            (numbered (Array.to_list (param_types (element_type (type_of llf)))))))
  in
  let hlprs_cpust_param_idx_map =
    List.fold_left
      (fun res llf -> LLMap.add llf (cpu_state_parameter_index llf) res)
      LLMap.empty
      (List.filter has_cpu_state_parameter (defined_functions llm))
  in
  (*
  LLMap.iter (fun llf idx ->
      pe (spr "%s (%d)" (value_name llf) idx)
    ) hlprs_cpust_param_idx_map;
     *)

  (*
   * find CPUState helpers which are called by CPUState helpers
   *)
(*
  LLMap.iter (fun llf idx ->
      iter_uses (fun llu ->
          match classify_value (user llu) with
            | ValueKind.Instruction _ ->
              let llf' = block_parent (instr_parent (user llu)) in
              pe (spr "%s\n  %s" (value_name llf') (string_of_llvalue (user llu)))
            | _ -> ()
        ) llf
    ) hlprs_cpust_param_idx_map;
*)
  (*
   * build call graph
   *)
  let cg = LLCallGraph.of_module llm in

  (*
   * look for strongly-connected components
   *)
  let sccl = LLCallGraphSCC.scc_list cg in
  let sccl' = List.filter (fun l -> List.length l > 1) sccl in
  if List.length sccl' > 0 then (
    pe (spr "Strongly connected components (%d):" (List.length sccl'));
    List.iter (fun comp ->
        List.iter (fun llf ->
            pe (value_name llf)
          ) comp
      ) sccl'
  ) else (
    pe "No strongly connected components."
  );

  (*
   * topologically sort functions
   *)
  let topol = LLCallGraphTopological.fold (fun llf res -> llf::res) cg [] in

  (*
   * in topological order, replace all uses with CPU state parameters with the
   * global CPUState variable we created, and replace operands corresponding to
   * those parameters with undef's
   *)
  List.iter (fun llf ->
      let cpustparam = param llf (LLMap.find llf hlprs_cpust_param_idx_map) in
      replace_all_uses_with cpustparam glblcpust;

      (* now replace caller CPUState operands with undef *)
      iter_uses (fun llu ->
          let ins = user llu in
          assert (classify_value ins = ValueKind.Instruction Opcode.Call &&
                  (operand ins ((num_operands ins) - 1)) = llf);
          set_operand
            ins
            (LLMap.find llf hlprs_cpust_param_idx_map)
            (undef cpustptrty)
        ) llf
  ) (List.filter has_cpu_state_parameter topol);

  (*
   * delete CPUState parameters from all functions
   *)
  let topol' = List.map 
      (delete_unused_function_parameters llm)
      (List.filter has_cpu_state_parameter topol) in

  (*
   * proceeding topologically, for every function f we
   * (1) analyze usage of CPUState
   * (2) use the results of the previous step to build a map from TCGGlobal's to
   * lists of GEP instructions
   * (3) for TCGGlobals which are loaded, (i) promote them to be function
   * parameters. for TCGGlobals which are stored, (ii) promote them to be return
   * values
   *
   * steps for (i):
   * (1) append TCGGlobal g's type to the parameter list of f
   * (2) if f is a helper function, add metadata to the llvm module noting that
   * the g was appended to the parameter list
   * (3) for every caller of f, build a GEP before the call instruction getting
   * the pointer to g, and then load it and pass it as the operand to the
   * parameter we just added
   * (5) at the head of f, add a local variable l to f by building an alloca of
   * g's type
   * (6) for every GEP gep to g in f, let the set of loads with pointer operand
   * gep be L
   * (7) replace the uses of every ld \in L with building a load to l
   *
   * steps for (ii):
   * (1) if the return type of f is void, then set the return type to be the
   * TCGGlobal g's type. otherwise if integer, set the return type to be a
   * struct with size 2 and the second field be the type of g. otherwise if
   * struct (last case), set the return type to be a struct with size n+1 where
   * n denotes the size of the current return struct type of f, where the last
   * struct field is of the type of g. afterwards, we will necessarily have to
   * modify the callers of f to appropriately get the original return value(s)
   * (the new parameter will have operand undef).
   * (2) if f is a helper function, add metadata to the llvm module noting that
   * the g was appended to the return values of f
   * (3) for every caller of f, get the return value of g and store it to the
   * CPUState via building a GEP
   * (4) for every GEP gep to g in f, let the set of stores with pointer operand
   * gep be S. using the local variable l (or creating it), we replace every
   * st \in S with a store to l.
   * (5) set the return value corresponding to g with l
   *
   * since (i) and (ii) both create local variables in f, (i) and (ii) will be
   * carried out together in a single procedure.
   *)

  (*
   * build offset to TCG global map
   *)
  let offtcggblmap = List.fold_left (fun res tcggbl ->
      IntMap.add (TCGGlobal.offset tcggbl) tcggbl res
    ) IntMap.empty tcgglbll in

  (*
   * function to analyze the usage of the CPUState, and find those pointers to
   * it which point to a TCG global.
   *)
  let global_cpu_state_geps_of_function llf =
    fold_left_uses
      (fun res llu ->
         let usr = user llu in
         if classify_value usr <> ValueKind.Instruction Opcode.GetElementPtr ||
            block_parent (instr_parent usr) <> llf ||
            not (does_gep_have_all_constant_indices usr) then (
           res
         ) else (
(*
           pe (spr "  %s" (string_of_llvalue usr));
           List.iter (fun llins -> pe (spr "    %s" (string_of_llvalue llins))) (users_of usr);
*)
           usr::res
         )
      )
      []
      glblcpust
  in

  List.iter (fun llf ->
(*
      pe (spr "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n%s\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" (value_name llf));
*)
      print_string (spr " %s" (value_name llf));

      (*
       * build map from TCG globals to lists of GEP's
       *)
      let tcggblaccesses = 
        List.fold_left
          (fun res gep ->
             let off = gep_accumulate_constant_offset llm gep in
             if not (IntMap.mem off offtcggblmap) then (
               res
             ) else (
               let tcggbl = IntMap.find off offtcggblmap in
               TCGGlobalMap.add
                 tcggbl
                 (try
                    gep::(TCGGlobalMap.find tcggbl res)
                  with
                  | Not_found -> [gep]
                  | _ -> assert false)
                 res
             )
          ) TCGGlobalMap.empty (global_cpu_state_geps_of_function llf) in

      (*
       * process every TCGGlobal.
       *)
      ignore (
        TCGGlobalMap.fold (fun tcggbl geps llf' ->
            (* first determine whether it's an input or output *)
            let gep = List.hd geps in
            let gep_users = List.concat (List.map users_of geps) in
            let gep_user_llval_kinds = List.map classify_value gep_users  in
            let inp = List.mem
                (ValueKind.Instruction Opcode.Load) gep_user_llval_kinds in
            let out = List.mem
                (ValueKind.Instruction Opcode.Store) gep_user_llval_kinds in

(*
          List.iter
            (fun llins -> pe (string_of_llvalue llins))
            (List.concat (List.map users_of geps));
*)

            if inp then (
              print_string (spr " < %s" (TCGGlobal.name tcggbl));
              HelperMetadata.add_input llf' (TCGGlobal.idx tcggbl)
            );

            if out then (
              print_string (spr " > %s" (TCGGlobal.name tcggbl));
              HelperMetadata.add_output llf' (TCGGlobal.idx tcggbl)
            );

            (*
             * promote inputs
             *)
            let llf'' =
              if inp then (
              (*
               * compute new parameter list
               *)
                let param_tys = param_types (element_type (type_of llf')) in
                let param_tys' =
                  Array.append
                    param_tys
                    [|TCGGlobal.ty tcggbl|] in

                let llf'' = change_function_parameters
                    llm
                    llf'
                    param_tys'
                    (Array.init (Array.length param_tys) id) in

                (* set new parameter names *)
                Array.iter
                  (set_value_name (TCGGlobal.name tcggbl))
                  (Array.sub (params llf'') (Array.length param_tys) 1);

                (* change callers to provide new input as operand *)
                iter_users (fun call ->
                    assert (classify_value call =
                            ValueKind.Instruction Opcode.Call);
                    let b = builder_before llctx call in
                    let gep' = instr_clone gep in
                    insert_into_builder
                      gep'
                      (spr "%s_ptr" (TCGGlobal.name tcggbl))
                      b;
                    let vl = build_load gep' (TCGGlobal.name tcggbl) b in
                    set_operand call ((num_operands call) - 2) vl
                  ) llf'';

                llf''
              ) else (
                llf'
              ) in

            (*
             * promote outputs
             *)
            let llf''' =
              if out then (
                (*
                 * compute new parameter list
                 *)
                let ret_ty = return_type (element_type (type_of llf'')) in
                let ret_ty', fix_return_value_uses =
                  match classify_type ret_ty with
                  | TypeKind.Void ->
                    (struct_type llctx [|TCGGlobal.ty tcggbl|],
                     (fun _ _ _ -> ()))
                  | TypeKind.Struct ->
                    (struct_type llctx
                       (Array.append
                          (struct_element_types ret_ty)
                          [|TCGGlobal.ty tcggbl|]),
                     (fun b call call' ->
                        iter_users (fun llins ->
                            assert (classify_value llins =
                                    ValueKind.Instruction Opcode.ExtractValue);

                            replace_all_uses_with
                              llins
                              (build_extractvalue
                                 call'
                                 (Int64.to_int
                                    (BatOption.get
                                       (int64_of_const (operand llins 1))))
                                 ""
                                 b);

                            delete_instruction llins
                          ) call;
                        ()))
                  | TypeKind.Integer ->
                    (struct_type llctx [|ret_ty; TCGGlobal.ty tcggbl|],
                     (fun b call call' ->
                        replace_all_uses_with
                          call
                          (build_extractvalue call' 0 "" b)))
                  | _ -> assert false
                in

                (*
                 * add promoted CPU state field outputs to return value
                 *)
                let llf''' = change_function_return
                    llm
                    llf''
                    ret_ty'
                    fix_return_value_uses in

                (*
                 * for every call of the new function, insert stores for the new
                 * outputs
                 *)
                iter_users (fun call ->
                    assert (classify_value call =
                            ValueKind.Instruction Opcode.Call);
                    let b = builder_after llctx call in
                    let gep' = instr_clone gep in
                    insert_into_builder
                      gep'
                      (spr "%s_ptr" (TCGGlobal.name tcggbl))
                      b;
                    let vl = build_extractvalue
                        call
                        (Array.length (struct_element_types ret_ty') - 1)
                        (TCGGlobal.name tcggbl)
                        b in
                    ignore (build_store vl gep' b)
                  ) llf''';
                llf'''
              ) else (
                llf''
              ) in

            (* create local *)
            let b = builder_before llctx (function_head_instruction llf''') in
            let lcl = build_alloca (TCGGlobal.ty tcggbl) "" b in

            (* initialize local with argument value *)
            if inp then
              ignore (build_store (param llf''' ((Array.length (params llf''')) - 1)) lcl b);
(*
            (* initialize local with value from CPUState *)
            let gep' = instr_clone gep in
            insert_into_builder
              gep'
              (spr "%s_ptr" (TCGGlobal.name tcggbl))
              b;
            ignore (
              build_store (build_load gep' (TCGGlobal.name tcggbl) b) lcl b);
*)
            (* identify loads & stores *)
            let lds = List.filter
                (fun llins -> classify_value llins =
                              ValueKind.Instruction Opcode.Load)
                gep_users in
            let sts = List.filter
                (fun llins -> classify_value llins =
                              ValueKind.Instruction Opcode.Store)
                gep_users in

            (* replace loads *)
            List.iter (fun ld ->
                position_before ld b;
                let nm = value_name ld in
                set_value_name "" ld;
                replace_all_uses_with ld (build_load lcl nm b);
              ) lds;

            (* replace stores *)
            List.iter (fun st ->
                position_before st b;
                ignore (build_store (operand st 0) lcl b)
              ) sts;

            (* delete stores to global CPUState *)
            List.iter delete_instruction sts;

            (* adjust rets *)
            if out then (
              let ret_ty = return_type (element_type (type_of llf''')) in
              assert (classify_type ret_ty  = TypeKind.Struct);
              let ret_ty_num_fields =
                Array.length (struct_element_types (ret_ty)) in
              let rets = return_instructions llf''' in
              if ret_ty_num_fields = 1 then (
                (* function previously returned void *)
                List.iter (fun ret ->
                    position_before ret b;
                    let vl = build_load lcl (TCGGlobal.name tcggbl) b in
                    ignore (build_ret (build_insertvalue (undef ret_ty) vl 0 "" b) b)
                  ) rets
              ) else if ret_ty_num_fields = 2 then (
                (* function previously returned int, OR it once returned void
                 * and then was turned into a function returning a struct with
                 * one field *)
                List.iter (fun ret ->
                    position_before ret b;
                    let vl = build_load lcl (TCGGlobal.name tcggbl) b in
                    let res =
                      if classify_type (type_of (operand ret 0)) =
                         TypeKind.Struct then
                        build_extractvalue (operand ret 0) 0 "" b
                      else
                        operand ret 0 in
                    let res' =
                      build_insertvalue (undef ret_ty) res 0 "" b in
                    let res'' =
                      build_insertvalue res' vl 1 "" b in

                    ignore (build_ret res'' b)
                  ) rets
              ) else (
                (* function previously returned a struct. need to extractvalue
                 * all of the previous fields from the value that is returned,
                 * and then insertvalue them into a struct of the new return
                 * type along with the new field *)
                List.iter (fun ret ->
                    position_before ret b;
                    let vl = build_load lcl (TCGGlobal.name tcggbl) b in
                    let res = operand ret 0 in

                    assert (classify_type (type_of res) = TypeKind.Struct);

                    let fields =
                      (List.map (fun idx ->
                           build_extractvalue res idx "" b)
                          (range 0 (ret_ty_num_fields - 1)))@[vl] in


                    let res' =
                      List.fold_left
                        (fun res' (idx, field) ->
                           build_insertvalue res' field idx "" b)
                        (undef ret_ty) (numbered fields) in

                    ignore (build_ret res' b)
                  ) rets
              );

              List.iter delete_instruction rets
            );

            llf'''
          ) tcggblaccesses llf);

      print_string "\n";
    ) topol';

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
