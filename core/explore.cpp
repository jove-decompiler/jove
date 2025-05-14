#include "explore.h"
#include "B.h"
#include "tcg.h"

#include <boost/format.hpp>
#include <boost/scope/defer.hpp>

#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <stdexcept>

namespace obj = llvm::object;

namespace jove {

typedef boost::format fmt;

template <bool MT, bool MinSize>
function_index_t explorer_t<MT, MinSize>::_explore_function(
    binary_t &b,
    obj::Binary &B,
    const taddr_t Addr,
    const bool Speculative) {
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  assert((Addr & 1) == 0);
#endif
  assert(is_taddr_valid(Addr));

  function_index_t Idx = invalid_function_index;
  {
    bool inserted;
    if constexpr (MT) {
      inserted = b.fnmap.try_emplace_or_cvisit(
          Addr, b, std::ref(Idx), [&](const auto &x) {
            Idx = static_cast<function_index_t>(x.second);
          });
    } else {
      auto it = b.fnmap.find(Addr);
      if (it == b.fnmap.end()) {
        inserted = b.fnmap.try_emplace(Addr, b, std::ref(Idx)).second;
        assert(inserted);
      } else {
        inserted = false;
        Idx = static_cast<function_index_t>((*it).second);
      }
    }

    assert(is_function_index_valid(Idx));

    if (likely(!inserted))
      return Idx;
  }

  function_t &f = b.Analysis.Functions.at(Idx);

  f.Speculative = Speculative;

  if (maybe_jv) {
    using OurCallers_t = Callers_t<MT, MinSize>;

    f.pCallers.Store(jv_file.construct<OurCallers_t>(
                         boost::interprocess::anonymous_instance)(
                         jv_file.get_segment_manager()),
                     std::memory_order_relaxed);
  }

  get_newfn_proc()(b, f);

  const basic_block_index_t EntryIdx =
      _explore_basic_block<false>(b, B, Addr, Speculative, Idx);

  assert(is_basic_block_index_valid(EntryIdx));

  f.Entry = EntryIdx;

  //
  // all blocks reachable from Entry now have f as a parent
  //
  auto &ICFG = b.Analysis.ICFG;

  std::function<void(bb_t bb)> rec = [&](bb_t bb) -> void {
    ICFG[bb].Parents.template insert(Idx, b);

    auto adj = ICFG.get_adjacent_vertices(bb);
    for (bb_t succ : adj) {
      // TODO: if succ has no other predecessors we can reuse new set

      //
      // if a successor already has this function marked as a parent, then we
      // can assume everything reachable from it is already too
      //
      if (ICFG[succ].Parents.template contains<MT>(Idx))
        continue;

      rec(succ);
    }
  };

  rec(basic_block_of_index(EntryIdx, ICFG));

  if (maybe_jv)
    ICFG[basic_block_of_index(EntryIdx, ICFG)].InvalidateAnalysis(*maybe_jv, b);

  return Idx;
}

template <bool MT, bool MinSize>
template <bool WithOnBlockProc>
bool explorer_t<MT, MinSize>::split(
    binary_t &b,
    obj::Binary &Bin,
    bbprop_t::exclusive_lock_guard<MT> e_lck_bb,
    bbmap_t::iterator it,
    const taddr_t Addr,
    basic_block_index_t Idx,
    onblockproc_t<MT> obp) {
  bbmap_t &bbmap = b.BBMap.map;
  auto &ICFG = b.Analysis.ICFG;

  assert(it != bbmap.end());

  const addr_intvl intvl = (*it).first;
  const basic_block_index_t BBIdx = (*it).second;

  const auto beg = intvl.first;
  const auto len = intvl.second;

  assert(Addr > beg);

  //
  // before splitting the basic block, let's check to make sure that the
  // new block doesn't start in the middle of an instruction. if that would
  // occur, we need to gtfo
  //
  {
    uint64_t InstLen = 0;
    for (uint64_t A = beg; A < beg + len; A += InstLen) {
      llvm::MCInst Inst;

      std::string errmsg;
      bool Disassembled;
      {
        llvm::raw_string_ostream ErrorStrStream(errmsg);

        const uint8_t *Ptr =
            reinterpret_cast<const uint8_t *>(B::toMappedAddr(Bin, A));

        Disassembled = disas.DisAsm->getInstruction(
            Inst, InstLen, llvm::ArrayRef<uint8_t>(Ptr, len), A,
            ErrorStrStream);
      }

      if (!Disassembled)
        throw std::runtime_error(std::string("failed to disassemble at ") +
                                 taddr2str(A) + " in \"" + b.Name.c_str() +
                                 "\"");

      if (A == Addr)
        goto on_insn;
    }

    return false; /* not on instruction! */
  }

on_insn:
  //
  // "Split" the block, i.e.
  //
  // ____________________
  // |                  |
  // |                  |
  // |                  |
  // |       bb_1       |  <---------------------
  // |                  |
  // |                  |
  // |                  |
  // --------CALL--------
  //
  // becomes
  //
  // _____________________
  // |                   |
  // |       bb_1        |
  // |                   |
  // |-------NONE--------|  <---------------------
  // |                   |
  // |       bb_2        |
  // |                   |
  // --------CALL---------
  //
  //

  const unsigned off = Addr - beg;

  const addr_intvl intvl_1(beg, off);
  const addr_intvl intvl_2(addr_intvl_upper(intvl_1),
                           addr_intvl_upper(intvl) - Addr);

  bb_t bb_1 = basic_block_of_index(BBIdx, ICFG);
  bbprop_t &bbprop_1 = ICFG.at(bb_1);

  //
  // create bb_2
  //
  bb_t bb_2 = basic_block_of_index(Idx, ICFG);
  bbprop_t &bbprop_2 = ICFG.at(bb_2);

  bbprop_2.Addr = addr_intvl_lower(intvl_2);
  bbprop_2.Size = intvl_2.second;
  bbprop_2.Sj = bbprop_1.Sj;
  bbprop_2.Term = bbprop_1.Term;
  bbprop_2.pDynTargets.Store(
      bbprop_1.pDynTargets.Load(std::memory_order_relaxed),
      std::memory_order_relaxed);
  //bbprop_2.InvalidateAnalysis();

  assert(bbprop_2.Addr + bbprop_2.Size == addr_intvl_upper(intvl));

  std::vector<bb_t> to_bb_vec;
  {
    bbprop_t::exclusive_lock_guard<MT> e_lck(bbprop_1.mtx);

    //
    // update bb_1
    //
    bbprop_1.Size = off;
    bbprop_1.Term.Type = TERMINATOR::NONE;
    bbprop_1.Term.Addr = 0;
    bbprop_1.Term._indirect_jump.IsLj = false;
    bbprop_1.Sj = false;
    bbprop_1.pDynTargets.Store(nullptr, std::memory_order_relaxed);
    bbprop_1.Analysis.Stale.store(true, std::memory_order_relaxed);

    //
    // gather up bb_1 edges
    //
    to_bb_vec.reserve(ICFG.template out_degree<false>(bb_1));
    {
      auto succ_it_pair = ICFG.adjacent_vertices(bb_1);

      std::copy(succ_it_pair.first,
                succ_it_pair.second,
                std::back_inserter(to_bb_vec));
    }

    //
    // bb_1 leads to bb_2
    //
    ICFG.template clear_out_edges<false>(bb_1);
    ICFG.template add_edge<false>(bb_1, bb_2);
  }

  {
    bbprop_t::exclusive_lock_guard<MT> e_lck(boost::move(e_lck_bb));

    //
    // edges from bb_1 now point from bb_2
    //
    for (bb_t bb : to_bb_vec)
      ICFG.template add_edge<false>(bb_2, bb);

    if constexpr (WithOnBlockProc)
      obp(bb_2, bbprop_2);
  }

  //
  // update bbmap
  //
#if 0
  assert(addr_intvl(bbprop_1.Addr, bbprop_1.Size) == intvl_1);
  assert(addr_intvl(bbprop_2.Addr, bbprop_2.Size) == intvl_2);

  assert(addr_intvl_disjoint(intvl_1, intvl_2));

  const unsigned sav_bbmap_size = bbmap.size();
#endif

  bbmap.erase(it);

#if 0
  assert(bbmap.size() == sav_bbmap_size - 1);

  assert(bbmap_find(bbmap, intvl_1) == bbmap.end());
  assert(bbmap_find(bbmap, intvl_2) == bbmap.end());
#endif

  bbmap_add(bbmap, intvl_1, BBIdx);
  bbmap_add(bbmap, intvl_2, Idx);

#if 0
  {
    auto _it = bbmap_find(bbmap, intvl_1);
    assert(_it != bbmap.end());
    assert((*_it).second == BBIdx);
  }

  {
    auto _it = bbmap_find(bbmap, intvl_2);
    assert(_it != bbmap.end());
    assert((*_it).second == Idx);
  }
#endif

  if (IsVeryVerbose())
    llvm::errs() << llvm::formatv("{0} | {1}\n",
                                  description_of_block(bbprop_1, false),
                                  description_of_block(bbprop_2, false));

  /* XXX should be be calling newbb proc? */
#if 0
  this->on_newbb_proc(b, basic_block_of_index(Idx, ICFG));
#endif

  return true;
}

template <bool MT, bool MinSize>
template <bool WithOnBlockProc>
basic_block_index_t
explorer_t<MT, MinSize>::_explore_basic_block(binary_t &b,
                                              obj::Binary &Bin,
                                              const taddr_t Addr,
                                              bool Speculative,
                                              const function_index_t ParentIdx,
                                              onblockproc_t<MT> obp,
                                              onblockproc_u_t obp_u) {
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  assert((Addr & 1) == 0);
#endif
  assert(Addr);

  auto &ICFG = b.Analysis.ICFG;

  basic_block_index_t Idx = invalid_basic_block_index;
  {
    bool inserted;
    if constexpr (MT) {
      inserted = b.bbbmap.try_emplace_or_cvisit(
          Addr, b, std::ref(Idx), static_cast<taddr_t>(Addr),
          [&](const auto &x) {
            Idx = static_cast<basic_block_index_t>(x.second);
          });
    } else {
      auto it = b.bbbmap.find(Addr);
      if (it == b.bbbmap.end()) {
        inserted =
            b.bbbmap
                .try_emplace(Addr, b, std::ref(Idx), static_cast<taddr_t>(Addr))
                .second;
        assert(inserted);
      } else {
        inserted = false;
        Idx = static_cast<basic_block_index_t>((*it).second);
      }
    }

    assert(is_basic_block_index_valid(Idx));

    if (!inserted) {
      if constexpr (WithOnBlockProc)
        obp_u(Idx);
      return Idx;
    }
  }

  auto &bbprop = ICFG[basic_block_of_index(Idx, ICFG)];
  bbprop_t::pub_t::exclusive_lock_guard<MT> e_lck_bb_pub(
      bbprop.pub.mtx, boost::interprocess::accept_ownership);
  bbprop_t::exclusive_lock_guard<MT> e_lck_bb(
      bbprop.mtx, boost::interprocess::accept_ownership);

  {
  BOOST_SCOPE_DEFER [&bbprop] {
      bbprop.pub.is.store(true, MT ? std::memory_order_release
                                   : std::memory_order_relaxed);
  };

  typename BBMap_t<MT>::template exclusive_lock_guard<MT> e_lck_bbmap(
      b.BBMap.mtx, boost::interprocess::defer_lock);
  bbmap_t &bbmap = b.BBMap.map;
  if (likely(!Speculative)) {
    e_lck_bbmap.lock();

    //
    // does this new basic block start in the middle of a previously-created
    // basic block?
    //
    auto it = bbmap_find(bbmap, Addr);
    if (it != bbmap.end()) {
      bool success;
      if constexpr (WithOnBlockProc)
        success = split<true>(b, Bin, boost::move(e_lck_bb), it, Addr, Idx, obp);
      else
        success = split<false>(b, Bin, boost::move(e_lck_bb), it, Addr, Idx);
      if (likely(success)) {
        return Idx;
      } else {
        //
        // splitting here would totally fuck up the CFG, so mark this block as
        // "speculative" and continue translation while leaving bbmap UNTOUCHED.
        //
        Speculative = true;

        if (true /* IsVerbose() */)
          llvm::errs() << llvm::formatv(
              "could not cleanly split at {0}+{1:x} ; {2}\n", b.Name.c_str(),
              Addr, addr_intvl2str((*it).first));
#if 1
        throw invalid_control_flow_exception(b, Addr);
#endif
      }
    }
  }

  //
  // We are *not* splitting!
  //
  tcg.set_binary(Bin);

  bool StartWasValid = false;
  unsigned Size = 0;
  jove::terminator_info_t T;

  if (IsVeryVerbose() &&
      unlikely(b.Analysis.objdump.template is_addr_bad<MT>(Addr)))
    llvm::errs() << llvm::formatv("objdump says {0}:{1:x} is BAD\n",
                                  b.Name.c_str(), Addr);

  do {
    try {
      unsigned size;
      std::tie(size, T) = tcg.translate(Addr + Size);

      Size += size;
      StartWasValid = true;
    } catch (const g2h_exception &e) {
      if (StartWasValid) {
        //
        // it's possible that the provided entry point *was* valid, but
        // something prevents the code from going further than the first
        // translate() call. so, have the block finish with an unreachable
        // terminator
        //
        T.Type = TERMINATOR::UNREACHABLE;
        T.Addr = ~0UL;
        break;
      }

      throw invalid_control_flow_exception(b, e.pc);
    } catch (const illegal_op_exception &e) {
      //
      // let's see what the LLVM disassembler thinks
      //
      const bool CanDisassemble = ({
        const uint8_t *const Ptr =
            reinterpret_cast<const uint8_t *>(B::toMappedAddr(Bin, e.pc));
        assert(Ptr);

        std::string errmsg;
        llvm::raw_string_ostream ErrorStrStream(errmsg);

        llvm::MCInst Inst;
        uint64_t InstLen;
        disas.DisAsm->getInstruction(
            Inst, InstLen,
            llvm::ArrayRef<uint8_t>(Ptr, 16 /* should be enough? */), e.pc,
            ErrorStrStream);
      });

      if (!CanDisassemble)
        throw invalid_control_flow_exception(b, e.pc); /* it's garbage */

      T.Type = TERMINATOR::UNREACHABLE;
      T.Addr = ~0UL;
      break;
    }

    if (likely(!Speculative)) {
      addr_intvl intervl(Addr, Size);
      auto it = bbmap_find(bbmap, intervl);
      if (it != bbmap.end()) {
        addr_intvl _intervl = (*it).first;

        assert(addr_intvl_lower(intervl) < addr_intvl_lower(_intervl));

        //
        // solution here is to prematurely end the basic block with a NONE
        // terminator, and with a next_insn address of _intervl.lower()
        //
        Size = addr_intvl_lower(_intervl) - addr_intvl_lower(intervl);
        T.Type = TERMINATOR::NONE;
        T.Addr = 0; /* XXX? */
        T._none.NextPC = addr_intvl_lower(_intervl);

        if (IsVeryVerbose()) {
          basic_block_index_t _BBIdx = (*it).second;
          bb_t _bb = basic_block_of_index(_BBIdx, ICFG);

          llvm::errs() << llvm::formatv(
              "OKAY {0} so {1} has size {2} TERM: {3}\t\t\t\t\t\t{4}\n",
              description_of_block(ICFG[_bb], false), addr_intvl2str(intervl),
              Size, description_of_terminator_info(T, false), b.Name.c_str());
        }

        break;
      }
    }

    if (T.Type == TERMINATOR::NONE) {
      if (b.Analysis.objdump.template is_addr_really_bad<MT>(T._none.NextPC)) {
        //
        // it's possible that something prevents the code from going further so,
        // have the block finish with an unreachable terminator.
        //
        // classic example of this is in arm64 [vdso], where last instruction
        // that appears is a noreturn svc(sigreturn)
        //
        if (IsVerbose()) {
          llvm::errs() << llvm::formatv(
              "objdump says really bad, no further @ {0}:{1:x}\n",
              b.Name.c_str(), T._none.NextPC);
#if 0
          llvm::errs() << llvm::formatv(
              "objdump is [{0:x}, {1:x})\n", b.Analysis.objdump.begin,
              b.Analysis.objdump.begin + b.Analysis.objdump.good.size());
#endif
        }

        T.Type = TERMINATOR::UNREACHABLE;
        T.Addr = ~0UL;
      }
    }
  } while (T.Type == TERMINATOR::NONE);

  if (unlikely(T.Type == TERMINATOR::UNKNOWN)) {
    llvm::WithColor::error()
        << (boost::format("%s: unknown terminator @ %#lx\n") % __func__ % Addr).str();

    const ELFF &Elf = llvm::cast<ELFO>(&Bin)->getELFFile();

    uint64_t InstLen;
    for (uint64_t A = Addr; A < Addr + Size; A += InstLen) {
      llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(A);
      if (!ExpectedPtr)
        throw std::runtime_error((fmt("%s: invalid address 0x%lx") % __func__ % A).str());

      llvm::MCInst Inst;
      bool Disassembled = disas.DisAsm->getInstruction(
          Inst, InstLen, llvm::ArrayRef<uint8_t>(*ExpectedPtr, Size), A,
          llvm::nulls());

      if (!Disassembled)
        throw std::runtime_error((fmt("%s: failed to disassemble %#lx") % __func__ % A).str());

      disas.IP->printInst(&Inst, A, "", *disas.STI, llvm::errs());
      llvm::errs() << '\n';
    }

    tcg.dump_operations();
    fputc('\n', stdout);
    abort();
  }

  {
    bbprop_t::exclusive_lock_guard<MT> e_lck(boost::move(e_lck_bb));

    bbprop.Speculative = Speculative;
    bbprop.Addr = Addr;
    bbprop.Size = Size;
    bbprop.Term.Type = T.Type;
    bbprop.Term.Addr = T.Addr;

    //bbprop.InvalidateAnalysis();
    if (is_function_index_valid(ParentIdx))
      bbprop.Parents.insert(ParentIdx, b);

    addr_intvl intervl(bbprop.Addr, bbprop.Size);
    if (likely(!Speculative)) {
      bbmap_add(bbmap, intervl, Idx);
      e_lck_bbmap.unlock();
    }

    bb_t bb = basic_block_of_index(Idx, ICFG);
    if constexpr (WithOnBlockProc)
      obp(bb, bbprop);

    //
    // a new basic block has been created and (maybe) added to bbmap
    //
    if (IsVeryVerbose())
      llvm::errs() << llvm::formatv(
          "{0} {1}\t\t\t\t\t\t{2}\n", description_of_block(bbprop, false),
          description_of_terminator_info(T, false), b.Name.c_str());

    get_newbb_proc()(b, bb);
  }

  auto control_flow_to = [&](taddr_t Target) -> void {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    Target &= ~1UL;
#endif

    _control_flow_to(
        b, Bin, T.Addr ?: Addr, Target, Speculative,
        basic_block_of_index(Idx, ICFG) /* unused if !Speculative */);
  };

  switch (T.Type) {
  case TERMINATOR::UNCONDITIONAL_JUMP:
    control_flow_to(T._unconditional_jump.Target);
    break;

  case TERMINATOR::CONDITIONAL_JUMP: {
#if 0
    // explore both destinations concurrently
    std::array<taddr_t, 2> Targets{{T._conditional_jump.Target,
                                     T._conditional_jump.NextPC}};
    std::for_each(maybe_par_unseq,
                  Targets.begin(),
                  Targets.end(),
                  [&](taddr_t Target) {
                    control_flow_to(Target);
                  });
#else
    control_flow_to(T._conditional_jump.Target);
    control_flow_to(T._conditional_jump.NextPC);
#endif
    break;
  }

  case TERMINATOR::CALL: {
    taddr_t CalleeAddr = T._call.Target;

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    CalleeAddr &= ~1UL;
#endif

#if 0
    if (CalleeAddr == 0) {
      //   8fedab:       e8 50 12 70 ff          call   0 <thread_id>
      throw std::runtime_error(
          (fmt("%s: call to zero @ 0x%lx") % __func__ % T.Addr).str());
    }
#endif

    function_index_t CalleeFIdx =
        _explore_function(b, Bin, CalleeAddr, Speculative);

    assert(is_function_index_valid(CalleeFIdx));

    if (is_binary_index_valid(b.Idx)) { /* may not know binary index */
      function_t &callee = b.Analysis.Functions.at(CalleeFIdx);

      if (callee.pCallers.Load(std::memory_order_relaxed))
        callee.Callers<MT, MinSize>().Insert(caller_t(b.Idx, T.Addr));

      if (maybe_jv) {
        jv_t &jv = *maybe_jv;

        const auto &ParentsVec = bbprop.Parents.template get<MT>();
        std::for_each(maybe_par_unseq,
                      ParentsVec.cbegin(),
                      ParentsVec.cend(), [&](function_index_t FIdx) {
                        function_t &caller = b.Analysis.Functions.at(FIdx);

                        jv.Analysis.ReverseCallGraph.template add_edge<MT>(
                            callee.ReverseCGVert(jv),
                            caller.ReverseCGVert(jv));
                      });
      }
    }

    if (unlikely(Speculative)) {
      ICFG[basic_block_of_index(Idx, ICFG)].Term._call.Target = CalleeFIdx;
    } else {
      auto s_lck_bbmap = b.BBMap.template shared_access<MT>();

      ICFG[basic_block_at_address(T.Addr, b)].Term._call.Target = CalleeFIdx;
    }

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

  case TERMINATOR::UNKNOWN:
  default:
    throw std::runtime_error(
        (fmt("%s: unknown terminator @ 0x%lx") % __func__ % T.Addr).str());
  }
  } /* pub */

  return Idx;
}

template <bool MT, bool MinSize>
void explorer_t<MT, MinSize>::_control_flow_to(
    binary_t &b,
    obj::Binary &Bin,
    const taddr_t TermAddr,
    const taddr_t Target,
    const bool Speculative, bb_t bb /* unused if !Speculative */) {
  assert(Target);

  if (IsVeryVerbose())
    llvm::errs() << llvm::formatv("  -> {0}\n", taddr2str(Target, false));

  basic_block_index_t SuccBBIdx = invalid_basic_block_index;
  try {
    SuccBBIdx = _explore_basic_block<false>(b, Bin, Target, Speculative);
  } catch (const invalid_control_flow_exception &e) {
    if (1 /* IsVerbose() */)
      llvm::errs() << llvm::formatv(
          "invalid control flow to {0} from {1} when exploring {2} in {3}\n",
          taddr2str(e.pc, false),
          taddr2str(TermAddr, false),
          taddr2str(Target, false),
          e.name_of_binary);

    throw e;
  }

  assert(is_basic_block_index_valid(SuccBBIdx));

  auto &ICFG = b.Analysis.ICFG;
  if (unlikely(Speculative)) {
    ICFG.add_edge(bb, basic_block_of_index(SuccBBIdx, b));
  } else {
    auto s_lck_bbmap = b.BBMap.template shared_access<MT>();

    ICFG.template add_edge<MT>(basic_block_at_address(TermAddr, b),
                               basic_block_of_index(SuccBBIdx, b));
  }
}

template <bool MT, bool MinSize>
basic_block_index_t explorer_t<MT, MinSize>::explore_basic_block(binary_t &b,
                                                        obj::Binary &B,
                                                        taddr_t Addr) {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  Addr &= ~1UL;
#endif

  return _explore_basic_block<false>(b, B, Addr, false);
}

template <bool MT, bool MinSize>
basic_block_index_t explorer_t<MT, MinSize>::explore_basic_block(
    binary_t &b,
    obj::Binary &B,
    taddr_t Addr,
    onblockproc_t<MT> obp,
    onblockproc_u_t obp_u) {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  Addr &= ~1UL;
#endif

  return _explore_basic_block<true>(b, B, Addr, false,
                                    invalid_function_index, obp, obp_u);
}

template <bool MT, bool MinSize>
function_index_t explorer_t<MT, MinSize>::explore_function(binary_t &b,
                                                  obj::Binary &B,
                                                  taddr_t Addr) {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  Addr &= ~1UL;
#endif

  return _explore_function(b, B, Addr, false);
}

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))
#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template struct explorer_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),         \
                             GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))>;
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
