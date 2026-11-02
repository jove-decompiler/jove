#include "explore.h"
#include "B.h"
#include "tcg.h"
#include "sjlj.h"
#include "tcg.h"

#include <boost/format.hpp>
#include <boost/scope/defer.hpp>
#include <boost/filesystem.hpp>

#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <stdexcept>

namespace obj = llvm::object;
namespace fs = boost::filesystem;

using llvm::WithColor;

namespace jove {

typedef boost::format fmt;

template <bool MT, bool MinSize>
function_index_t explorer_t<MT, MinSize>::_explore_function(
    binary_t &b,
    B::cached::type<> &cachedb,
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

  get_newfn_proc()(b, f);

  const basic_block_index_t EntryIdx =
      _explore_basic_block<false>(b, cachedb, Addr, Speculative, Idx);

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
    ICFG[basic_block_of_index(EntryIdx, ICFG)].InvalidateAnalyses(*maybe_jv, b, EntryIdx);

  return Idx;
}

template <bool MT, bool MinSize>
template <bool WithOnBlockProc>
bool explorer_t<MT, MinSize>::split(
    binary_t &b,
    B::cached::type<> &cachedb,
    bbprop_t::exclusive_lock_guard<MT> e_lck_bb,
    bbmap_t::iterator it,
    const taddr_t Addr,
    basic_block_index_t Idx,
    onblockproc_t<MT> obp) {
  bbmap_t *const pbbmap = b.BBMap.map.get();
  assert(pbbmap);
  bbmap_t &bbmap = *pbbmap;
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
            reinterpret_cast<const uint8_t *>(B::cached::toMappedAddr(cachedb, A));

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
  // "Split" the block, e.g.
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
  assert(bbprop_2.Analysis.Stale.test(boost::memory_order_relaxed));

  assert(bbprop_2.Addr + bbprop_2.Size == addr_intvl_upper(intvl));

  std::vector<bb_t> to_bb_vec;
  void *const pDynTargets = ({
    bbprop_t::exclusive_lock_guard<MT> e_lck(bbprop_1.mtx);

    //
    // update bb_1
    //
    bbprop_1.Size = off;
    bbprop_1.Term.Type = TERMINATOR::NONE;
    bbprop_1.Term.Addr = 0;
    bbprop_1.Lj = false;
    bbprop_1.Sj = false;
    bbprop_1.Analysis.Stale.test_and_set(boost::memory_order_relaxed);

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

    bbprop_1.pDynTargets.exchange(nullptr, boost::memory_order_relaxed);
  });

  {
    bbprop_t::exclusive_lock_guard<MT> e_lck(boost::move(e_lck_bb));

    bbprop_2.pDynTargets.store(pDynTargets, boost::memory_order_relaxed);

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
                                              B::cached::type<> &cachedb,
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

  //
  // if a bbprop_t was created with MT=false, we won't do the following. if that
  // indeed happened, and move construction changes to MT=1, the locks will
  // be promptly unlocked in the move constructor of binary_analysis_t.
  //
  auto &bbprop = ICFG[basic_block_of_index(Idx, ICFG)];
  bbprop_t::pub_t::exclusive_lock_guard<MT> e_lck_bb_pub(
      bbprop.pub.mtx, boost::interprocess::accept_ownership);
  bbprop_t::exclusive_lock_guard<MT> e_lck_bb(
      bbprop.mtx, boost::interprocess::accept_ownership);

  {
  BOOST_SCOPE_DEFER [&] {
      bbprop.pub.is.test_and_set(MT ? boost::memory_order_release
                                    : boost::memory_order_relaxed);
    if (maybe_jv)
      (*maybe_jv).generation.fetch_add(1, boost::memory_order_relaxed);
  };

  typename BBMap_t<MT>::exclusive_lock_guard e_lck_bbmap(
      b.BBMap.mtx, boost::interprocess::defer_lock);

  bbmap_t *const pbbmap = b.BBMap.map.get();
  assert(pbbmap);
  bbmap_t &bbmap = *pbbmap;

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
        success = split<true>(b, cachedb, boost::move(e_lck_bb), it, Addr, Idx, obp);
      else
        success = split<false>(b, cachedb, boost::move(e_lck_bb), it, Addr, Idx);
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
  bool StartWasValid = false;
  unsigned Size = 0;
  jove::terminator_info_t T;

  if (IsVeryVerbose() && unlikely(b.Analysis.objdump_thinks.is_addr_bad(Addr)))
    WithColor::note() << llvm::formatv("objdump says {0}:{1:x} is BAD\n",
                                       b.Name.c_str(), Addr);

  do {
    try {
      unsigned size;
      std::tie(size, T) = tcg.translate(cachedb, Addr + Size);

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
            reinterpret_cast<const uint8_t *>(B::cached::toMappedAddr(cachedb, e.pc));
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
      if (b.Analysis.objdump_thinks.is_addr_really_bad(T._none.NextPC)) {
        //
        // it's possible that something prevents the code from going further so,
        // have the block finish with an unreachable terminator.
        //
        // classic example of this is in arm64 [vdso], where last instruction
        // that appears is a noreturn svc(sigreturn)
        //
        if (IsVerbose()) {
          llvm::errs() << llvm::formatv(
              "no further @ {0}:{1:x}, out-of-bounds address (objdump)\n",
              b.Name.c_str(), T._none.NextPC);
#if 0
          llvm::errs() << llvm::formatv(
              "objdump is [{0:x}, {1:x})\n", b.Analysis.objdump_thinks.begin,
              b.Analysis.objdump_thinks.begin + b.Analysis.objdump_thinks.good.size());
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

    uint64_t InstLen;
    for (uint64_t A = Addr; A < Addr + Size; A += InstLen) {
      const uint8_t *Ptr = static_cast<const uint8_t *>(B::cached::toMappedAddr(cachedb, A));
      if (!Ptr)
        throw std::runtime_error((fmt("%s: invalid address 0x%lx") % __func__ % A).str());

      llvm::MCInst Inst;
      bool Disassembled = disas.DisAsm->getInstruction(
          Inst, InstLen, llvm::ArrayRef<uint8_t>(Ptr, Size), A, llvm::nulls());

      if (!Disassembled)
        throw std::runtime_error((fmt("%s: failed to disassemble %#lx") % __func__ % A).str());

      disas.IP->printInst(&Inst, A, "", *disas.STI, llvm::errs());
      llvm::errs() << '\n';
    }

    tcg.dump_ops(stderr);
    abort();
  }

  {
    bbprop_t::exclusive_lock_guard<MT> e_lck(boost::move(e_lck_bb));

    bbprop.Speculative = Speculative;
    bbprop.Addr = Addr;
    bbprop.Size = Size;
    bbprop.Term.Type = T.Type;
    bbprop.Term.Addr = T.Addr;

#if defined(TARGET_X86_64) || defined(TARGET_I386)
    bbprop.Term._conditional_jump.String = T._conditional_jump.String;
#endif

    assert(bbprop.Analysis.Stale.test(boost::memory_order_relaxed));

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

    get_newbb_proc()(b, bbprop, Idx);
  }

  auto control_flow_to = [&](taddr_t Target) -> void {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    Target &= ~1UL;
#endif

    _control_flow_to(
        b, cachedb, T.Addr ?: Addr, Target, Speculative,
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

    assert(T.Addr);
    function_index_t CalleeFIdx =
        _explore_function(b, cachedb, CalleeAddr, Speculative);

    assert(is_function_index_valid(CalleeFIdx));

    if (unlikely(Speculative)) {
      assert(bbprop.Term.Type == TERMINATOR::CALL);

      bbprop.Term._call.Target = CalleeFIdx;
    } else {
      auto s_lck_bbmap = b.BBMap.shared_access();

      if (bbprop.Term.Type == TERMINATOR::CALL)
        bbprop.Term._call.Target = CalleeFIdx;
      else
        ICFG[basic_block_at_address(T.Addr, b)].Term._call.Target = CalleeFIdx;
    }

    if (is_binary_index_valid(b.Idx)) { /* may not know binary index */
      function_t &callee = b.Analysis.Functions.at(CalleeFIdx);

      if (callee.Analysis.pCallers.load(boost::memory_order_relaxed))
        callee.Analysis.AddCaller<MT, MinSize>(caller_t(b.Idx, T.Addr));

      if (maybe_jv) {
        jv_t &jv = *maybe_jv;

        const auto &ParentsVec = bbprop.Parents.template get<MT>();
        std::for_each(maybe_par_unseq,
                      ParentsVec.cbegin(),
                      ParentsVec.cend(), [&](function_index_t FIdx) {
                        function_t &caller = b.Analysis.Functions.at(FIdx);

                        jv.Analysis.ReverseCallGraph.template add_edge<MT>(
                            callee.Analysis.ReverseCGVert(jv),
                            caller.Analysis.ReverseCGVert(jv));
                      });
      }
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
    B::cached::type<> &cachedb,
    const taddr_t TermAddr,
    const taddr_t Target,
    const bool Speculative, bb_t bb /* unused if !Speculative */) {
  assert(Target);

  if (IsVeryVerbose())
    llvm::errs() << llvm::formatv("  -> {0}\n", taddr2str(Target, false));

  basic_block_index_t SuccBBIdx = invalid_basic_block_index;
  try {
    SuccBBIdx = _explore_basic_block<false>(b, cachedb, Target, Speculative);
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
    auto s_lck_bbmap = b.BBMap.shared_access();

    ICFG.template add_edge<MT>(basic_block_at_address(TermAddr, b),
                               basic_block_of_index(SuccBBIdx, b));
  }
}

template <bool MT, bool MinSize>
basic_block_index_t explorer_t<MT, MinSize>::explore_basic_block(binary_t &b,
                                                                 B::cached::type<> &cachedb,
                                                                 taddr_t Addr) {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  Addr &= ~1UL;
#endif

  return _explore_basic_block<false>(b, cachedb, Addr, false);
}

template <bool MT, bool MinSize>
basic_block_index_t explorer_t<MT, MinSize>::explore_basic_block(
    binary_t &b,
    B::cached::type<> &cachedb,
    taddr_t Addr,
    onblockproc_t<MT> obp,
    onblockproc_u_t obp_u) {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  Addr &= ~1UL;
#endif

  return _explore_basic_block<true>(b, cachedb, Addr, false, invalid_function_index,
                                    obp, obp_u);
}

template <bool MT, bool MinSize>
function_index_t explorer_t<MT, MinSize>::explore_function(binary_t &b,
                                                           B::cached::type<> &cachedb,
                                                           taddr_t Addr) {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  Addr &= ~1UL;
#endif

  return _explore_function(b, cachedb, Addr, false);
}

#include "relocs_common.hpp"

template <bool MT, bool MinSize>
void explorer_t<MT, MinSize>::explore_binary(
    binary_t &b,
    B::cached::type<> &cachedb,
    const AddOptions_t &Options) {
  B::ref Bin = cachedb.first.get();

  b.IsDynamicLinker = false;
  b.IsExecutable = false;
  b.IsVDSO = false;

  b.IsPIC = true;
  b.IsDynamicallyLoaded = false;

  auto BasicBlockAtAddress = [&](uint64_t Entrypoint) -> basic_block_index_t {
    if (!Entrypoint)
      return invalid_basic_block_index;

    if (Options.Objdump && b.Analysis.objdump_thinks.is_addr_bad(Entrypoint)) {
      if (Options.IsVeryVerbose())
        llvm::errs() << llvm::formatv("objdump rejects {0}:{1:x}\n",
                                      b.Name.c_str(), Entrypoint);
      return invalid_basic_block_index;
    }

    if (Options.IsVeryVerbose())
      llvm::errs() << llvm::formatv("exploring {0}:{1:x}\n", b.Name.c_str(),
                                    Entrypoint);

    return this->explore_basic_block(b, cachedb, Entrypoint);
  };
  auto FunctionAtAddress = [&](uint64_t Entrypoint) -> function_index_t {
    if (!Entrypoint)
      return invalid_function_index;

    // let's be extra careful.
    if (unlikely(!is_basic_block_index_valid(BasicBlockAtAddress(Entrypoint))))
      return invalid_function_index;

    return this->explore_function(b, cachedb, Entrypoint);
  };
  auto ABIAtAddress = [&](uint64_t Entrypoint) -> void {
    function_index_t FIdx = FunctionAtAddress(Entrypoint);

    if (unlikely(!is_function_index_valid(FIdx)))
      return;

    b.Analysis.Functions.at(FIdx).IsABI = true;
  };

  B::_elf(Bin,
    [&](ELFO &O) {
  const ELFF &Elf = O.getELFFile();

  switch (Elf.getHeader().e_type) {
  case llvm::ELF::ET_NONE:
    throw std::runtime_error("given binary has unknown type");

  case llvm::ELF::ET_REL:
    throw std::runtime_error("given binary is object file");

  case llvm::ELF::ET_EXEC:
    b.IsPIC = false;
    break;

  case llvm::ELF::ET_DYN:
    break;

  case llvm::ELF::ET_CORE:
    throw std::runtime_error("given binary is core file");

  default:
    abort();
    break;
  }

  elf::DynRegionInfo DynamicTable(O);
  elf::loadDynamicTable(O, DynamicTable);

  //assert(DynamicTable.Addr);

  auto dynamic_table = [&](void) -> Elf_Dyn_Range {
    if (DynamicTable.Addr)
      return DynamicTable.getAsArrayRef<Elf_Dyn>();
    else
      return {};
  };

#if 0
  bool IsStaticallyLinked = true;
#endif

  //
  // examine dynamic table
  //
  for (const Elf_Dyn &Dyn : dynamic_table()) {
    if (unlikely(Dyn.getTag() == llvm::ELF::DT_NULL))
      break; /* marks end of dynamic table. */

    switch (Dyn.d_tag) {
#if 0
    case llvm::ELF::DT_NEEDED:
      IsStaticallyLinked = false;
      break;
#endif
    case llvm::ELF::DT_INIT:
      ABIAtAddress(Dyn.getVal());
      break;
    }
  }

  llvm::Expected<Elf_Phdr_Range> ExpectedPrgHdrs = Elf.program_headers();
  if (!ExpectedPrgHdrs)
    throw std::runtime_error("no program headers in ELF. bug?");

  auto PrgHdrs = *ExpectedPrgHdrs;

  //
  // if the ELF has a PT_INTERP program header, then we'll explore the entry
  // point. if not, we'll only consider it if it's statically-linked (i.Elf. it's
  // the dynamic linker)
  //
  bool HasInterpreter =
    std::any_of(PrgHdrs.begin(),
                PrgHdrs.end(),
                [](const Elf_Phdr &Phdr) -> bool{ return Phdr.p_type == llvm::ELF::PT_INTERP; });
  uint64_t EntryAddr = Elf.getHeader().e_entry;
  if (EntryAddr) {
#if 0
    llvm::outs() << llvm::formatv("entry point @ {0:x}\n", EntryAddr);
#endif

    b.Analysis.EntryFunction = FunctionAtAddress(EntryAddr);
  } else {
    b.Analysis.EntryFunction = invalid_function_index;
  }

  //
  // search local symbols (if they exist)
  //
  {
    llvm::Expected<Elf_Shdr_Range> ExpectedSections = Elf.sections();

    if (ExpectedSections) {
      const Elf_Shdr *SymTab = nullptr;

      for (const Elf_Shdr &Sect : *ExpectedSections) {
        if (Sect.sh_type == llvm::ELF::SHT_SYMTAB) {
          SymTab = &Sect;
          break;
        }
      }

      if (SymTab) {
        llvm::Expected<Elf_Sym_Range> ExpectedLocalSyms = Elf.symbols(SymTab);

        if (ExpectedLocalSyms) {
          auto LocalSyms = *ExpectedLocalSyms;

          for_each_if(LocalSyms.begin(),
                      LocalSyms.end(),
                      [](const Elf_Sym &Sym) -> bool {
                        return !Sym.isUndefined() &&
                                Sym.getType() == llvm::ELF::STT_FUNC;
                      },
                      [&](const Elf_Sym &Sym) -> void {
                        BasicBlockAtAddress(Sym.st_value);
                      });
        }
      }
    }
  }

  //
  // look for split debug information
  //
  std::optional<llvm::ArrayRef<uint8_t>> optionalBuildID = elf::getBuildID(Elf);
  if (optionalBuildID) {
    llvm::ArrayRef<uint8_t> BuildID = *optionalBuildID;

    fs::path splitDbgInfo =
        fs::path("/usr/lib/debug") / ".build-id" /
        llvm::toHex(BuildID[0], /*LowerCase=*/true) /
        (llvm::toHex(BuildID.slice(1), /*LowerCase=*/true) + ".debug");

    if (fs::exists(splitDbgInfo)) {
    std::vector<uint8_t> SplitBinBytes;
    auto SplitBin = B::CreateFromFile(splitDbgInfo.c_str(), SplitBinBytes);

    B::_elf(SplitBin.get(), [&](ELFO &split_Obj) -> void {
#if 0
      WithColor::note() << llvm::formatv("found split debug info file {0}\n",
                                         splitDbgInfo.c_str());
#endif

      const ELFF &split_Elf = split_Obj.getELFFile();

      //
      // examine local symbols (if they exist)
      //
      llvm::Expected<Elf_Shdr_Range> ExpectedSections = split_Elf.sections();
      if (ExpectedSections && !(*ExpectedSections).empty()) {
        const Elf_Shdr *SymTab = nullptr;

        for (const Elf_Shdr &Sec : *ExpectedSections) {
          if (Sec.sh_type == llvm::ELF::SHT_SYMTAB) {
            SymTab = &Sec;
            break;
          }
        }

        if (SymTab) {
          llvm::Expected<Elf_Sym_Range> ExpectedLocalSyms =
              split_Elf.symbols(SymTab);

          if (ExpectedLocalSyms) {
            auto LocalSyms = *ExpectedLocalSyms;

            for_each_if(LocalSyms.begin(),
                        LocalSyms.end(),
                        [](const Elf_Sym &Sym) -> bool {
                          return !Sym.isUndefined() &&
                                  Sym.getType() == llvm::ELF::STT_FUNC;
                        },
                        [&](const Elf_Sym &Sym) -> void {
                          BasicBlockAtAddress(Sym.st_value);
                        });
          }
        }
      }
    });
    } else {
      //WithColor::note() << llvm::formatv("build ID is {0}, no split debug found at {1}\n", llvm::toHex(BuildID, /*LowerCase=*/true), splitDbgInfo.string());
    }
  } else {
    //WithColor::note() << "no build ID\n";
  }

  llvm::StringRef DynamicStringTable;
  const Elf_Shdr *SymbolVersionSection = nullptr;
  std::vector<elf::VersionMapEntry> VersionMap;
  std::optional<elf::DynRegionInfo> OptionalDynSymRegion;

  if (DynamicTable.Addr)
    OptionalDynSymRegion =
        loadDynamicSymbols(O,
                           DynamicTable,
                           DynamicStringTable,
                           SymbolVersionSection,
                           VersionMap);

  //
  // examine exported functions
  //
  if (OptionalDynSymRegion) {
    auto DynSyms = OptionalDynSymRegion->getAsArrayRef<Elf_Sym>();

    for_each_if(DynSyms.begin(),
                DynSyms.end(),
                [](const Elf_Sym &Sym) -> bool {
                  return !Sym.isUndefined() &&
                          Sym.getType() == llvm::ELF::STT_FUNC;
                },
                [&](const Elf_Sym &Sym) -> void {
                  FunctionAtAddress(Sym.st_value);
                });

    for_each_if(DynSyms.begin(),
                DynSyms.end(),
                [](const Elf_Sym &Sym) -> bool {
                  return !Sym.isUndefined() &&
                          Sym.getType() == llvm::ELF::STT_GNU_IFUNC;
                },
                [&](const Elf_Sym &Sym) -> void {
                  ABIAtAddress(Sym.st_value);
                });

    //
    // XXX __libc_early_init (glibc)
    //
    if (SymbolVersionSection) {
      for_each_if(
          DynSyms.begin(),
          DynSyms.end(),
          [](const Elf_Sym &Sym) -> bool {
            return !Sym.isUndefined() &&
                   Sym.getType() == llvm::ELF::STT_FUNC;
          },
          [&](const Elf_Sym &Sym) -> void {
            llvm::Expected<llvm::StringRef> ExpectedSymName =
                Sym.getName(DynamicStringTable);

            if (!ExpectedSymName)
              return;

            llvm::StringRef SymName = *ExpectedSymName;
            llvm::StringRef SymVers;

            // Determine the position in the symbol table of this entry.
            size_t EntryIndex = (reinterpret_cast<uintptr_t>(&Sym) -
                                 reinterpret_cast<uintptr_t>(OptionalDynSymRegion->Addr)) /
                                sizeof(Elf_Sym);

            // Get the corresponding version index entry.
            llvm::Expected<const Elf_Versym *> ExpectedVersym =
                Elf.getEntry<Elf_Versym>(*SymbolVersionSection, EntryIndex);

            bool IsDefault;
            if (ExpectedVersym)
              SymVers = getSymbolVersionByIndex(VersionMap,
                                                DynamicStringTable,
                                                (*ExpectedVersym)->vs_index,
                                                IsDefault);

            if (SymName == "__libc_early_init" &&
                SymVers == "GLIBC_PRIVATE")
              ABIAtAddress(Sym.st_value);
          });
    }
  }

  //
  // search for constructor/deconstructor array
  //
  struct {
    uint64_t Beg, End;
  } InitArray = {0u, 0u};

  struct {
    uint64_t Beg, End;
  } FiniArray = {0u, 0u};

  {
    llvm::Expected<Elf_Shdr_Range> ExpectedSections = Elf.sections();

    if (ExpectedSections) {
      for (const Elf_Shdr &Sect : *ExpectedSections) {
        switch (Sect.sh_type) {
        case llvm::ELF::SHT_INIT_ARRAY:
          InitArray.Beg = Sect.sh_addr;
          InitArray.End = Sect.sh_addr + Sect.sh_size;
          break;
        case llvm::ELF::SHT_FINI_ARRAY:
          FiniArray.Beg = Sect.sh_addr;
          FiniArray.End = Sect.sh_addr + Sect.sh_size;
          break;
        }
      }
    }
  }

  //
  // examine relocations
  //
  elf::DynRegionInfo DynRelRegion(O);
  elf::DynRegionInfo DynRelaRegion(O);
  elf::DynRegionInfo DynRelrRegion(O);
  elf::DynRegionInfo DynPLTRelRegion(O);

  if (DynamicTable.Addr)
    loadDynamicRelocations(O,
                           DynamicTable,
                           DynRelRegion,
                           DynRelaRegion,
                           DynRelrRegion,
                           DynPLTRelRegion);

  //
  // Search for IFunc relocations and make their resolver functions be ABIs
  //
  {
    auto processDynamicReloc = [&](const elf::Relocation &R) -> void {
      //
      // ifunc resolvers are ABIs
      //
      if (elf_is_irelative_relocation(R)) {
        uint64_t resolverAddr = R.Addend ? *R.Addend : 0;

        if (!resolverAddr) {
          llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(R.Offset);
          if (ExpectedPtr)
            resolverAddr = B::extractAddress(Bin, *ExpectedPtr);
        }

        if (resolverAddr)
          ABIAtAddress(resolverAddr);
      }
    };

    for_each_dynamic_relocation(Elf,
                                DynRelRegion,
                                DynRelaRegion,
                                DynRelrRegion,
                                DynPLTRelRegion,
                                processDynamicReloc);
  }

  //
  // Search for relocations in .init_array/.fini_array and make the
  // constructor/deconstructor functions be ABIs
  //
  {
    auto processDynamicReloc = [&](const elf::Relocation &R) -> void {
      bool Contained = (R.Offset >= InitArray.Beg &&
                        R.Offset < InitArray.End) ||
                       (R.Offset >= FiniArray.Beg &&
                        R.Offset < FiniArray.End);
      if (!Contained)
        return;

      if (!elf_is_relative_relocation(R)) {
#if 0
        WithColor::warning() << llvm::formatv(
            "unrecognized relocation {0} in .init_array/.fini_array\n",
            Elf.getRelocationTypeName(R.Type));
#endif
        return;
      }

      //
      // constructors/deconstructors are ABIs
      //
      uint64_t Addr = R.Addend ? *R.Addend : 0;
      if (!Addr) {
        llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(R.Offset);

        if (ExpectedPtr)
          Addr = B::extractAddress(Bin, *ExpectedPtr);
      }

#if 0
      if (Options.IsVerbose())
        WithColor::note() << llvm::formatv("ctor/dtor: off={0:x} Addr={1:x}\n",
                                           R.Offset, Addr);
#endif

      if (Addr)
        ABIAtAddress(Addr);
    };

    for_each_dynamic_relocation(Elf,
                                DynRelRegion,
                                DynRelaRegion,
                                DynRelrRegion,
                                DynPLTRelRegion,
                                processDynamicReloc);
  }
    });

  B::_coff(Bin,
    [&](COFFO &O) {
      //b.IsExecutable = O.getCharacteristics() & llvm::COFF::IMAGE_FILE_DLL;

      uint64_t entryRVA = 0;
      if (const obj::pe32plus_header *PEPlusHeader = O.getPE32PlusHeader()) {
        entryRVA = PEPlusHeader->AddressOfEntryPoint;
        b.IsPIC = PEPlusHeader->DLLCharacteristics &
                  llvm::COFF::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE;
      } else if (const obj::pe32_header *PEHeader = O.getPE32Header()) {
        entryRVA = PEHeader->AddressOfEntryPoint;
        b.IsPIC = PEHeader->DLLCharacteristics &
                  llvm::COFF::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE;
      }

      if (entryRVA)
        b.Analysis.EntryFunction = FunctionAtAddress(coff::va_of_rva(O, entryRVA));

      auto exp_itr = O.export_directories();
      for_each_if(exp_itr.begin(),
                  exp_itr.end(),
                  [&](const obj::ExportDirectoryEntryRef &Exp) -> bool {
                    llvm::StringRef Name;
                    uint32_t Ordinal;
                    bool IsForwarder;
                    uint32_t RVA;

                    return !llvm::errorToBool(Exp.getSymbolName(Name)) &&
                           !llvm::errorToBool(Exp.getOrdinal(Ordinal)) &&
                           !llvm::errorToBool(Exp.isForwarder(IsForwarder)) &&
                           !IsForwarder &&
                           !llvm::errorToBool(Exp.getExportRVA(RVA)) &&
                           coff::isCode(O, coff::va_of_rva(O, RVA));
                  },
                  [&](const obj::ExportDirectoryEntryRef &Exp) -> void {
                      uint32_t RVA;
                      bool iserr = llvm::errorToBool(Exp.getExportRVA(RVA));
                      assert(!iserr);

                      ABIAtAddress(coff::va_of_rva(O, RVA));
                  });

      for_each_if(O.symbol_begin(),
                  O.symbol_end(),
                  [&](obj::SymbolRef SymbolRef) -> bool {
                    llvm::Expected<uint64_t> AddrOrErr = SymbolRef.getAddress();
                    if (!AddrOrErr) {
                      llvm::consumeError(AddrOrErr.takeError());
                      return false;
                    }

                    obj::COFFSymbolRef Symbol = O.getCOFFSymbol(SymbolRef);

                    if (Symbol.getNumberOfAuxSymbols() > 0)
                      return false;

                    llvm::Expected<llvm::StringRef> NameOrErr = O.getSymbolName(Symbol);
                    if (!NameOrErr) {
                      llvm::consumeError(NameOrErr.takeError());
                      return false;
                    }

                    llvm::Expected<obj::section_iterator> ItOrErr = SymbolRef.getSection();

                    if (!ItOrErr) {
                      llvm::consumeError(ItOrErr.takeError());
                      return false;
                    }

                    obj::section_iterator it = *ItOrErr;
                    if (it == O.section_end())
                      return false;

                    const obj::coff_section *Section = O.getCOFFSection(*it);
                    return Section && Section->Characteristics & llvm::COFF::IMAGE_SCN_MEM_EXECUTE;
                  },
                  [&](obj::SymbolRef SymbolRef) -> void {
                    obj::COFFSymbolRef Symbol = O.getCOFFSymbol(SymbolRef);

#if 0
                    llvm::Expected<llvm::StringRef> NameOrErr = O.getSymbolName(Symbol);
                    assert(NameOrErr);

                    llvm::errs() << "exploring " << *NameOrErr << ' ' << Symbol.getValue() <<  " @ " << taddr2str(coff::va_of_rva(O, Symbol.getValue())) << '\n';
#endif

                    auto AddrOrErr = SymbolRef.getAddress();
                    assert(AddrOrErr);

                    ABIAtAddress(*AddrOrErr);
                  });

      // XXX we cannot completely rely on isCode() to tell us whether something
      // is code, so the following is #ifdef'd out- none of these addresses are
      // necessarily functions.
#if 0
      coff::for_each_base_relocation(
          O, [&](uint8_t RelocType, uint64_t RVA) -> void {
            if (!coff_is_dir_relocation(RelocType))
              return;

            const void *Ptr = coff::toMappedAddr(O, coff::va_of_rva(O, RVA));
            if (!Ptr)
              return;
            uint64_t Addr = B::extractAddress(O, Ptr);
            if (coff::isCode(O, Addr))
              ABIAtAddress(Addr);
          });
#endif
    }
  );

  if (Options.SjLj)
    ScanForSjLj(b, cachedb, *this);
}

template <bool MT, bool MinSize>
bool explorer_t<MT, MinSize>::fix_ambiguous_indirect_jump(
    binary_t &b,
    B::cached::type<> &cachedb,
    taddr_t TermAddr) {
  std::vector<taddr_t> SuccAddrVec;

  typename ip_icfg_base_t<MT>::vertex_descriptor bb;

  auto &ICFG = b.Analysis.ICFG;
  aassert(maybe_jv);
  jv_t &jv = *maybe_jv;

  {
    auto s_lck_bbmap = b.BBMap.shared_access();

    bb = basic_block_at_address(TermAddr, b);

    if (!IsAmbiguousIndirectJump(ICFG, bb))
      return false;

    auto e_lck = ICFG[bb].template exclusive_access<MT>();

    auto succ_it_pair = ICFG.adjacent_vertices(bb);

    SuccAddrVec.resize(ICFG.template out_degree<false>(bb));
    std::transform(
        succ_it_pair.first,
        succ_it_pair.second, SuccAddrVec.begin(),
        [&](bb_t bb) -> taddr_t { return ICFG.at(bb).Addr; });
  }

  std::vector<function_index_t> SuccFIdxVec;
  SuccFIdxVec.resize(SuccAddrVec.size());
  std::transform(std::execution::seq,
                 SuccAddrVec.begin(),
                 SuccAddrVec.end(),
                 SuccFIdxVec.begin(), [&](taddr_t Addr) -> function_index_t {
                   function_index_t res =
                       this->explore_function(b, cachedb, Addr);
                   assert(is_function_index_valid(res));
                   return res;
                 });

  {
    aassert(maybe_jv);
    jv_t &jv = *maybe_jv;

    auto s_lck_bbmap = b.BBMap.shared_access();

    ICFG.template clear_out_edges<MT>(bb); /* ambiguous no more */

    bb_t bb = basic_block_at_address(TermAddr, b);
    auto &bbprop = ICFG[bb];
    std::for_each(maybe_par_unseq,
                  SuccFIdxVec.cbegin(),
                  SuccFIdxVec.cend(), [&](function_index_t FIdx) {
                    bbprop.insertDynTarget(index_of_binary(b, jv),
                                           {index_of_binary(b, jv), FIdx}, jv);
                  });
    bbprop.InvalidateAnalyses(jv, b, index_of_basic_block(ICFG, bb));
  }

  return true;
}

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))
#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template class explorer_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),          \
                            GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))>;
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
