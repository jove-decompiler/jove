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
let fst3 (x, _, _) = x
let snd3 (_, x, _) = x
let thd3 (_, _, x) = x
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
  type t = TCGGlobalType.t * int * string

  let ty = fst3
  let offset = snd3
  let name = thd3

  let hash tcggbl =
    Hashtbl.hash (offset tcggbl)

  let compare tcggbl1 tcggbl2 =
    Pervasives.compare (offset tcggbl1) (offset tcggbl2)

  let equal tcggbl1 tcggbl2 =
    offset tcggbl1 = offset tcggbl2
end

module TCGGlobalMap = Map.Make(TCGGlobal)

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
   * validate & parse arguments
   *)
  if !ifp = "" || not (Sys.file_exists !ifp) || !ofp = "" then
    assert false;

  let tcgglbll = List.map (fun (ty_s, off_s, nm) ->
      let ty =
        match ty_s with
        | "I32" -> TCGGlobalType.I32
        | "I64" -> TCGGlobalType.I64
        | "COUNT" -> TCGGlobalType.COUNT
        | _ -> assert false
      in
      let off = sscan off_s "%d" id in
      (ty, off, nm)
    ) (List.map tuple_of_list3 (split 3 !args)) in

  (*
   * LLVM initialization
   *)
  let llctx = create_context () in

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
   * add CPUState thread-local global variable
   *)
  let glblcpust = define_global "cpu_state" (const_null cpustty) llm in
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
   * build offset to TCG global map
   *)
  let offtcggblmap = List.fold_left (fun res tcggbl ->
      IntMap.add (TCGGlobal.offset tcggbl) tcggbl res
    ) IntMap.empty tcgglbll in

  (*
   * analyze the usage of the CPUState, and find those pointers to it which
   * point to a TCG global.
   *)
  let gblcpust_uses_in_fn_map =
    fold_left_uses
      (fun res llu ->
        let usr = user llu in
        if classify_value usr <> ValueKind.Instruction Opcode.GetElementPtr ||
           not (does_gep_have_all_constant_indices usr) then (
          res
        ) else (
          let llf = block_parent (instr_parent usr) in
          LLMap.add
            llf
            (usr::(LLMap.find llf res))
            res
        )
      )
      (List.fold_left
         (fun res llf -> LLMap.add llf [] res)
         LLMap.empty
         topol')
      glblcpust in

  let fntcggaccesses = (* list of maps from TCG globals to lists of GEP's *)
    List.fold_left (fun res llf ->
(*
        print_string (value_name llf);
        List.iter (fun gep ->
            print_string (spr " %d" (gep_accumulate_constant_offset llm gep))
          ) (LLMap.find llf gblcpust_uses_in_fn_map);
        print_string "\n";
*)

        let res' =
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
                      TCGGlobalMap.find tcggbl res
                    with | Not_found -> [] | _ -> gep::(TCGGlobalMap.find tcggbl res))
                   res
               )
            ) TCGGlobalMap.empty (LLMap.find llf gblcpust_uses_in_fn_map) in
        res@[res']
      ) [] topol' in

  List.iter2 (fun llf tcgglgeps ->
      print_string (value_name llf);
      TCGGlobalMap.iter (fun k _ ->
          print_string (spr " %s" (TCGGlobal.name k))
        ) tcgglgeps;
      print_string "\n";
    ) topol' fntcggaccesses;

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
