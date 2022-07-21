#include "explore.h"
#include "elf.h"
#include <boost/format.hpp>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

namespace jove {

function_index_t explore_function(binary_t &b,
                                  llvm::object::Binary &B,
                                  tiny_code_generator_t &tcg,
                                  disas_t &dis,
                                  const tcg_uintptr_t Addr,
                                  fnmap_t &fnmap,
                                  bbmap_t &bbmap,
                                  std::function<void(binary_t &, basic_block_t, disas_t &)> on_newbb_proc) {
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  assert((Addr & 1) == 0);
#endif

  {
    auto it = fnmap.find(Addr);
    if (it != fnmap.end())
      return (*it).second;
  }

  const function_index_t res = b.Analysis.Functions.size();
  (void)b.Analysis.Functions.emplace_back();

  fnmap.insert({Addr, res});

  basic_block_index_t Entry =
      explore_basic_block(b, B, tcg, dis, Addr, fnmap, bbmap, on_newbb_proc);

#ifdef WARN_ON
  WARN_ON(!is_basic_block_index_valid(Entry));
#endif

  {
    function_t &f = b.Analysis.Functions[res];

    f.Analysis.Stale = true;
    f.IsABI = false;
    f.IsSignalHandler = false;
    f.Entry = Entry;
  }

  return res;
}

basic_block_index_t explore_basic_block(binary_t &b,
                                        llvm::object::Binary &B,
                                        tiny_code_generator_t &tcg,
                                        disas_t &dis,
                                        const tcg_uintptr_t Addr,
                                        fnmap_t &fnmap,
                                        bbmap_t &bbmap,
                                        std::function<void(binary_t &, basic_block_t, disas_t &)> on_newbb_proc) {
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  assert((Addr & 1) == 0);
#endif

  auto &ICFG = b.Analysis.ICFG;
  auto &ObjectFile = B;

  //
  // does this new basic block start in the middle of a previously-created
  // basic block?
  //
  {
    auto it = bbmap.find(Addr);
    if (it != bbmap.end()) {
      const basic_block_index_t BBIdx = -1+(*it).second;
      basic_block_t bb = boost::vertex(BBIdx, ICFG);

      assert(BBIdx < boost::num_vertices(ICFG));

      uintptr_t beg = ICFG[bb].Addr;

      if (Addr == beg) {
        assert(ICFG[bb].Addr == (*it).first.lower());
        return BBIdx;
      }

      //
      // before splitting the basic block, let's check to make sure that the
      // new block doesn't start in the middle of an instruction. if that would
      // occur, then we will assume the control-flow is invalid
      //
      {
        llvm::MCDisassembler &DisAsm = std::get<0>(dis);
        const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
        llvm::MCInstPrinter &IP = std::get<2>(dis);

        const ELFF &E = *llvm::cast<ELFO>(&ObjectFile)->getELFFile();

        uint64_t InstLen = 0;
        for (tcg_uintptr_t A = beg; A < beg + ICFG[bb].Size; A += InstLen) {
          llvm::MCInst Inst;

          std::string errmsg;
          bool Disassembled;
          {
            llvm::raw_string_ostream ErrorStrStream(errmsg);

            llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(A);
            if (!ExpectedPtr)
              abort();

            Disassembled = DisAsm.getInstruction(
                Inst, InstLen,
                llvm::ArrayRef<uint8_t>(*ExpectedPtr, ICFG[bb].Size), A,
                ErrorStrStream);
          }

          if (!Disassembled) {
            llvm::WithColor::error() << llvm::formatv(
                "failed to disassemble {0:x}: {1}\n", A, errmsg);

	    return invalid_basic_block_index;
	  }

          if (A == Addr)
            goto on_insn_boundary;
        }

        llvm::WithColor::error() << llvm::formatv(
            "control flow to {0:x} in {1} doesn't lie on instruction boundary\n",
            Addr, b.Path);

        return invalid_basic_block_index;

on_insn_boundary:
        //
        // proceed.
        //
        ;
      }

      std::vector<basic_block_t> out_verts;
      {
        icfg_t::out_edge_iterator e_it, e_it_end;
        for (std::tie(e_it, e_it_end) = boost::out_edges(bb, ICFG);
             e_it != e_it_end; ++e_it)
          out_verts.push_back(boost::target(*e_it, ICFG));
      }

      // if we get here, we know that beg != Addr
      assert(Addr > beg);

      ptrdiff_t off = Addr - beg;
      assert(off > 0);

      boost::icl::interval<tcg_uintptr_t>::type orig_intervl = (*it).first;

      const basic_block_index_t NewBBIdx = boost::num_vertices(ICFG);
      basic_block_t newbb = boost::add_vertex(ICFG);
      {
        basic_block_properties_t &newbbprop = ICFG[newbb];
        newbbprop.Addr = beg;
        newbbprop.Size = off;
        newbbprop.Term.Type = TERMINATOR::NONE;
        newbbprop.Term.Addr = 0; /* XXX? */
        newbbprop.DynTargetsComplete = false;
        newbbprop.Term._call.Target = invalid_function_index;
        newbbprop.Term._call.Returns = false;
        newbbprop.Term._indirect_jump.IsLj = false;
        newbbprop.Sj = false;
        newbbprop.Term._indirect_call.Returns = false;
        newbbprop.Term._return.Returns = false;
        newbbprop.InvalidateAnalysis();
      }

      ICFG[bb].InvalidateAnalysis();

      std::swap(ICFG[bb], ICFG[newbb]);
      ICFG[newbb].Addr = Addr;
      ICFG[newbb].Size -= off;

      assert(ICFG[newbb].Addr + ICFG[newbb].Size == orig_intervl.upper());

      boost::clear_out_edges(bb, ICFG);
      boost::add_edge(bb, newbb, ICFG);

      for (basic_block_t out_vert : out_verts) {
        boost::add_edge(newbb, out_vert, ICFG);
      }

      assert(ICFG[bb].Term.Type == TERMINATOR::NONE);
      assert(boost::out_degree(bb, ICFG) == 1);

      boost::icl::interval<tcg_uintptr_t>::type intervl1 =
          boost::icl::interval<tcg_uintptr_t>::right_open(
              ICFG[bb].Addr, ICFG[bb].Addr + ICFG[bb].Size);

      boost::icl::interval<tcg_uintptr_t>::type intervl2 =
          boost::icl::interval<tcg_uintptr_t>::right_open(
              ICFG[newbb].Addr, ICFG[newbb].Addr + ICFG[newbb].Size);

      assert(boost::icl::disjoint(intervl1, intervl2));

      unsigned n = bbmap.iterative_size();
      bbmap.erase((*it).first);
      assert(bbmap.iterative_size() == n - 1);

      assert(bbmap.find(intervl1) == bbmap.end());
      assert(bbmap.find(intervl2) == bbmap.end());

      bbmap.add({intervl1, 1+BBIdx});
      bbmap.add({intervl2, 1+NewBBIdx});

      {
        auto _it = bbmap.find(intervl1);
        assert(_it != bbmap.end());
        assert((*_it).second == 1+BBIdx);
      }

      {
        auto _it = bbmap.find(intervl2);
        assert(_it != bbmap.end());
        assert((*_it).second == 1+NewBBIdx);
      }

      return NewBBIdx;
    }
  }

  tcg.set_binary(ObjectFile);

  unsigned Size = 0;
  jove::terminator_info_t T;
  do {
    unsigned size;
    std::tie(size, T) = tcg.translate(Addr + Size);

    Size += size;

    {
      boost::icl::interval<tcg_uintptr_t>::type intervl =
          boost::icl::interval<tcg_uintptr_t>::right_open(Addr, Addr + Size);
      auto it = bbmap.find(intervl);
      if (it != bbmap.end()) {
        const boost::icl::interval<tcg_uintptr_t>::type &_intervl = (*it).first;

        assert(intervl.lower() < _intervl.lower());

        //
        // solution here is to prematurely end the basic block with a NONE
        // terminator, and with a next_insn address of _intervl.lower()
        //
        Size = _intervl.lower() - intervl.lower();
        T.Type = TERMINATOR::NONE;
        T.Addr = 0; /* XXX? */
        T._none.NextPC = _intervl.lower();
        break;
      }
    }
  } while (T.Type == TERMINATOR::NONE);

  if (T.Type == TERMINATOR::UNKNOWN) {
    llvm::WithColor::error()
        << (boost::format("%s: unknown terminator @ %#lx\n") % __func__ % Addr).str();

    llvm::MCDisassembler &DisAsm = std::get<0>(dis);
    const llvm::MCSubtargetInfo &STI = std::get<1>(dis);
    llvm::MCInstPrinter &IP = std::get<2>(dis);

    const ELFF &E = *llvm::cast<ELFO>(&ObjectFile)->getELFFile();

    uint64_t InstLen;
    for (tcg_uintptr_t A = Addr; A < Addr + Size; A += InstLen) {
      llvm::Expected<const uint8_t *> ExpectedPtr = E.toMappedAddr(A);
      if (!ExpectedPtr)
        abort();

      llvm::MCInst Inst;
      bool Disassembled = DisAsm.getInstruction(
          Inst, InstLen, llvm::ArrayRef<uint8_t>(*ExpectedPtr, Size), A,
          llvm::nulls());

      if (!Disassembled) {
        llvm::WithColor::error()
            << (boost::format("%s: failed to disassemble %#lx\n") % __func__ % Addr).str();
        break;
      }

      IP.printInst(&Inst, A, "", STI, llvm::errs());
      llvm::errs() << '\n';
    }

    tcg.dump_operations();
    fputc('\n', stdout);
    return invalid_basic_block_index;
  }

  const basic_block_index_t BBIdx = boost::num_vertices(ICFG);
  basic_block_t bb = boost::add_vertex(ICFG);
  {
    basic_block_properties_t &bbprop = ICFG[bb];
    bbprop.Addr = Addr;
    bbprop.Size = Size;
    bbprop.Term.Type = T.Type;
    bbprop.Term.Addr = T.Addr;
    bbprop.DynTargetsComplete = false;
    bbprop.Term._call.Target = invalid_function_index;
    bbprop.Term._call.Returns = false;
    bbprop.Term._indirect_jump.IsLj = false;
    bbprop.Sj = false;
    bbprop.Term._indirect_call.Returns = false;
    bbprop.Term._return.Returns = false;
    bbprop.InvalidateAnalysis();

    boost::icl::interval<tcg_uintptr_t>::type intervl =
        boost::icl::interval<tcg_uintptr_t>::right_open(bbprop.Addr,
                                                        bbprop.Addr + bbprop.Size);
    assert(bbmap.find(intervl) == bbmap.end());
    bbmap.add({intervl, 1+BBIdx});
  }

  //
  // a new basic block has been created
  //
  on_newbb_proc(b, bb, dis);

  auto control_flow_to = [&](tcg_uintptr_t Target) -> void {
    assert(Target);

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    Target &= ~1UL;
#endif

    basic_block_index_t SuccBBIdx =
        explore_basic_block(b, B, tcg, dis, Target, fnmap, bbmap, on_newbb_proc);

    if (!is_basic_block_index_valid(SuccBBIdx)) {
      llvm::WithColor::warning() << llvm::formatv(
          "control_flow_to: invalid edge {0:x} -> {1:x}\n", T.Addr, Target);
      return;
    }

    bb = basic_block_at_address(T.Addr ?: Addr, b, bbmap);
    assert(T.Type == ICFG[bb].Term.Type);

    bool isNewTarget =
        boost::add_edge(bb, basic_block_of_index(SuccBBIdx, b), ICFG).second;
    (void)isNewTarget;
  };

  switch (T.Type) {
  case TERMINATOR::UNCONDITIONAL_JUMP:
    control_flow_to(T._unconditional_jump.Target);
    break;

  case TERMINATOR::CONDITIONAL_JUMP:
    control_flow_to(T._conditional_jump.Target);
    control_flow_to(T._conditional_jump.NextPC);
    break;

  case TERMINATOR::CALL: {
    tcg_uintptr_t CalleeAddr = T._call.Target;

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    CalleeAddr &= ~1UL;
#endif

    function_index_t CalleeFIdx = explore_function(b, B, tcg, dis, CalleeAddr,
                                                   fnmap,
                                                   bbmap,
                                                   on_newbb_proc);

    bb = basic_block_at_address(T.Addr, b, bbmap); /* bb may have been split */
    assert(ICFG[bb].Term.Type == TERMINATOR::CALL);

    ICFG[bb].Term._call.Target = CalleeFIdx;

    if (!is_function_index_valid(CalleeFIdx)) {
      llvm::WithColor::warning() << llvm::formatv(
          "explore_basic_block: invalid call @ {0:x}\n", T.Addr);
      break;
    }

    if (does_function_return(b.Analysis.Functions[CalleeFIdx], b))
      control_flow_to(T._call.NextPC);

    break;
  }

  case TERMINATOR::INDIRECT_CALL:
    //control_flow_to(T._indirect_call.NextPC);
    break;

  case TERMINATOR::INDIRECT_JUMP:
  case TERMINATOR::RETURN:
  case TERMINATOR::UNREACHABLE:
    break;

  case TERMINATOR::NONE:
    control_flow_to(T._none.NextPC);
    break;

  default:
    abort();
  }

  return BBIdx;
}

}
