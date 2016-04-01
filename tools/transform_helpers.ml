open Llvm

let main () =
  let ifp = ref "" in
  let ofp = ref "" in
  let arch_s = ref "" in

  let args = ref [||] in

  Arg.parse
    [
      ("-i", Arg.Set_string ifp,
       "Specify input LLVM bitcode file");

      ("-o", Arg.Set_string ofp,
       "Specify output LLVM bitcode file")

      ("--arch", Arg.Set_string arch_s,
       "Specify architecture (x86_64, i386, arm, mipsel)")
    ]
    (fun anonarg -> args := Array.append !args [|anonarg|])
    "usage: transform-helpers -i helpers -o helpers";

  (*
   * validate arguments
   *)
  if !ifp = "" || not (Sys.file_exists !ifp) || !ofp = "" then
    assert false;

  (*
   * LLVM initialization
   *)
  let llctx = create_context () in

  (*
   * parse input
   *)
  let llm = Llvm_bitreader.parse_bitcode llctx (MemoryBuffer.of_file !ifp) in

  (*
   * helpful functions
   *)
  let llvm_function_of_symbol sym = BatOption.get (lookup_function sym llm) in
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
