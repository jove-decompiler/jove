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

module TCGGlobalType  = struct
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

  let hash = Hashtbl.hash
  let compare = Pervasives.compare
  let equal f1 f2 = (compare f1 f2 = 0)
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
   * validate & parse arguments
   *)
  if !ifp = "" || not (Sys.file_exists !ifp) || !ofp = "" then
    assert false;

  let tcgglbll = List.map (fun l ->
      assert (List.length l = 3);
      let ty = match List.nth l 0 with
        | "I32" -> TCGGlobalType.I32
        | "I64" -> TCGGlobalType.I64
        | "COUNT" -> TCGGlobalType.COUNT
        | _ -> assert false
      in
      let off = sscan (List.nth l 1) "%d" id in
      let nm = List.nth l 2 in
      (ty, off, nm)
    ) (split 3 !args) in

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
   * add global variable
   *)
  let topol = LLCallGraphTopological.fold (fun llf res -> llf::res) cg [] in

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
  let hlprs_cpust_arg_idx_map =
    fold_left_functions (fun res llf ->
        if has_cpu_state_parameter llf then
          LLMap.add llf (cpu_state_parameter_index llf) res
        else
          res
      ) LLMap.empty llm
  in
  (*
  LLMap.iter (fun llf idx ->
      pe (spr "%s (%d)" (value_name llf) idx)
    ) hlprs_cpust_arg_idx_map;
     *)

  (*
   * find CPUState helpers which are called by CPUState helpers
   *)
  LLMap.iter (fun llf idx ->
      iter_uses (fun llu ->
          match classify_value (user llu) with
            | ValueKind.Instruction _ ->
              let llf' = block_parent (instr_parent (user llu)) in
              pe (spr "%s\n  %s" (value_name llf') (string_of_llvalue (user llu)))
            | _ -> ()
        ) llf
    ) hlprs_cpust_arg_idx_map;

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
