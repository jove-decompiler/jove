#include "explore.h"
#include "elf.h"
#include "tcg.h"

#include <boost/format.hpp>

#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/WithColor.h>

#include <stdexcept>

#include <oneapi/tbb/parallel_for_each.h>

namespace obj = llvm::object;

namespace jove {

typedef boost::format fmt;

#if 0
static void dump_bbmap(const bbmap_t &bbmap) {
  llvm::errs() << "==<BBMAP>==\n";
  for (const auto &x : bbmap) {
    llvm::errs() << addr_intvl2str(x.first) << " : " << x.second << '\n';
  }
  llvm::errs() << "==</BBMAP>==\n";
}
#endif

function_index_t explorer_t::_explore_function(binary_t &b,
                                               obj::Binary &B,
                                               const uint64_t Addr,
                                               process_later_t process_later) {
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  assert((Addr & 1) == 0);
#endif

  auto &fnmap = b.fnmap;

  function_index_t res = invalid_function_index;

  //
  // fast path
  //
  {
    bool found = fnmap.cvisit(Addr, [&](const auto &x) { res = x.second; });
    if (likely(found)) {
      assert(is_function_index_valid(res));
      return res;
    }
  }

  {
    ip_upgradable_lock<ip_upgradable_mutex> u_lck(b.fnmap_mtx);

    bool found = fnmap.cvisit(Addr, [&](const auto &x) { res = x.second; });
    if (likely(found)) {
      assert(is_function_index_valid(res));
      return res;
    }

    ip_scoped_lock<ip_upgradable_mutex> e_lck(boost::move(u_lck));

    res = b.Analysis.Functions.size();

    {
      function_t &f = b.Analysis.Functions.emplace_back();

      f.Idx = res;
      f.BIdx = index_of_binary(b, jv);
      f.Entry = invalid_basic_block_index;
    }

    bool succeeded = fnmap.emplace(Addr, res);
    assert(succeeded);
  }

  const basic_block_index_t Entry =
      _explore_basic_block(b, B, Addr, process_later);

  assert(is_basic_block_index_valid(Entry));

  function_t &f = b.Analysis.Functions.at(res);

  f.Analysis.Stale = true;
  f.IsABI = false;
  f.IsSignalHandler = false;
  f.Entry = Entry;

  return res;
}

basic_block_index_t explorer_t::_explore_basic_block(binary_t &b,
                                                     obj::Binary &Bin,
                                                     const uint64_t Addr,
                                                     process_later_t process_later) {
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
  assert((Addr & 1) == 0);
#endif

  auto &ICFG = b.Analysis.ICFG;

  assert(llvm::isa<ELFO>(&Bin));

  //
  // fast path
  //
  {
    basic_block_index_t BBIdx = invalid_basic_block_index;

    bool found = b.bbbmap.cvisit(Addr, [&](const auto &x) { BBIdx = x.second; });
    if (likely(found)) {
      assert(is_basic_block_index_valid(BBIdx));
      return BBIdx;
    }
  }

  auto &bbmap = b.bbmap;

  //
  // does this new basic block start in the middle of a previously-created
  // basic block?
  //
top:
  const bool gonna_split = ({
    ip_sharable_lock<ip_upgradable_mutex> s_lck(b.bbmap_mtx);

    auto it = bbmap_find(bbmap, Addr);

    bool res = it != bbmap.end();
    if (res && Addr == addr_intvl_lower((*it).first))
      return (*it).second; /* the same */

    res;
  });

  if (!gonna_split) {
    ip_scoped_lock<ip_mutex> e_lck(b.na_bbmap_mtx);

    if (b.bbmap_na) {
      b.na_cond.wait(e_lck, [&](void) -> bool { return !b.bbmap_na; });
      goto top;
    } else {
      b.bbmap_na = true;
    }
  } else {
    ip_upgradable_lock<ip_upgradable_mutex> u_lck(b.bbmap_mtx);

    auto it = bbmap_find(bbmap, Addr);
    assert(it != bbmap.end());

    const addr_intvl intvl = (*it).first;
    const basic_block_index_t BBIdx = (*it).second;

    const auto &beg = intvl.first;
    const auto &len = intvl.second;

    assert(Addr > beg);

    //
    // before splitting the basic block, let's check to make sure that the
    // new block doesn't start in the middle of an instruction. if that would
    // occur, then we will assume the control-flow is invalid
    //
    {
      const ELFF &Elf = llvm::cast<ELFO>(&Bin)->getELFFile();

      uint64_t InstLen = 0;
      for (uint64_t A = beg; A < beg + len; A += InstLen) {
        llvm::MCInst Inst;

        std::string errmsg;
        bool Disassembled;
        {
          llvm::raw_string_ostream ErrorStrStream(errmsg);

          llvm::Expected<const uint8_t *> ExpectedPtr = Elf.toMappedAddr(A);
          if (!ExpectedPtr)
            throw std::runtime_error(
                (fmt("%s: invalid address 0x%lx") % __func__ % A).str());

          Disassembled = disas.DisAsm->getInstruction(
              Inst, InstLen, llvm::ArrayRef<uint8_t>(*ExpectedPtr, len), A,
              ErrorStrStream);
        }

        if (!Disassembled)
          throw std::runtime_error(
              (fmt("%s: failed to disassemble 0x%lx%s%s") % __func__ % A %
               (errmsg.empty() ? "" : ": ") % errmsg).str());

        if (A == Addr)
          goto on_insn_boundary;
      }

      throw std::runtime_error((fmt("%s: control flow to 0x%lx doesn't lie on "
                                    "instruction boundary") % __func__ % Addr).str());

    on_insn_boundary:
        //
        // proceed.
        //
        ;
    }

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

    basic_block_t bb_1 = basic_block_of_index(BBIdx, ICFG);

    //
    // gather up bb_1 edges
    //
    std::vector<basic_block_t> to_bb_vec;
    to_bb_vec.reserve(boost::out_degree(bb_1, ICFG));
    {
      icfg_t::adjacency_iterator succ_it, succ_it_end;
      std::tie(succ_it, succ_it_end) = boost::adjacent_vertices(bb_1, ICFG);

      std::copy(succ_it, succ_it_end, std::back_inserter(to_bb_vec));
    }

    basic_block_properties_t &bbprop_1 = ICFG[bb_1];

    ip_scoped_lock<ip_upgradable_mutex> e_lck(boost::move(u_lck));

    //
    // create bb_2
    //
    basic_block_t bb_2 = boost::add_vertex(ICFG, jv.Binaries.get_allocator());
    const basic_block_index_t NewBBIdx = index_of_basic_block(ICFG, bb_2);
    basic_block_properties_t &bbprop_2 = ICFG[bb_2];

    bbprop_2.Addr = addr_intvl_lower(intvl_2);
    bbprop_2.Size = intvl_2.second;
    bbprop_2.Sj = false;
    bbprop_2.Term = bbprop_1.Term; /* terminator stolen from bb_1 */
    bbprop_2.DynTargetsComplete = bbprop_1.DynTargetsComplete;
    bbprop_2.InvalidateAnalysis();

    //
    // update bb_1
    //
    bbprop_1.Size = off;
    bbprop_1.Term.Type = TERMINATOR::NONE;
    bbprop_1.Term.Addr = 0;
    bbprop_1.Sj = false;
    bbprop_1.pDynTargets =
        boost::interprocess::offset_ptr<ip_dynamic_target_set>();
    bbprop_1.DynTargetsComplete = false;
    bbprop_1.InvalidateAnalysis();

    //
    // edges from bb_1 now point from bb_2
    //
    {
      boost::clear_out_edges(bb_1, ICFG);
      boost::add_edge(bb_1, bb_2, ICFG);

      for (basic_block_t bb : to_bb_vec)
        boost::add_edge(bb_2, bb, ICFG);
    }

    //
    // update bbmap
    //
    bbmap.erase(it);
    bbmap_add(bbmap, intvl_1, BBIdx);
    bbmap_add(bbmap, intvl_2, NewBBIdx);

    //
    // update bbbmap
    //
    {
      bool success = b.bbbmap.emplace(Addr, NewBBIdx);
      assert(success);
    }

    return NewBBIdx;
  }

  //
  // !gonna_split
  //
  tcg.set_binary(Bin);

  unsigned Size = 0;
  jove::terminator_info_t T;
  do {
    unsigned size;
    std::tie(size, T) = tcg.translate(Addr + Size);

    Size += size;

    {
      ip_sharable_lock<ip_upgradable_mutex> s_lck(b.bbmap_mtx);

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
        break;
      }
    }
  } while (T.Type == TERMINATOR::NONE);

  if (T.Type == TERMINATOR::UNKNOWN) {
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
    return invalid_basic_block_index;
  }

  basic_block_index_t BBIdx;
  basic_block_t bb;
  {
    ip_scoped_lock<ip_upgradable_mutex> e_lck(b.bbmap_mtx);

    BBIdx = boost::num_vertices(ICFG);
    bb = boost::add_vertex(ICFG, jv.Binaries.get_allocator());
    {
      basic_block_properties_t &bbprop = ICFG[bb];
      bbprop.Addr = Addr;
      bbprop.Size = Size;
      bbprop.Term.Type = T.Type;
      bbprop.Term.Addr = T.Addr;
      bbprop.DynTargetsComplete = false;
      bbprop.Term._call.Target = invalid_function_index;
      bbprop.Term._call.Returns = false;
      bbprop.Term._call.ReturnsOff = 0;
      bbprop.Term._indirect_jump.IsLj = false;
      bbprop.Sj = false;
      bbprop.Term._indirect_call.Returns = false;
      bbprop.Term._indirect_call.ReturnsOff = 0;
      bbprop.Term._return.Returns = false;
      bbprop.InvalidateAnalysis();

      addr_intvl intervl(bbprop.Addr, bbprop.Size);
      bbmap_add(bbmap, intervl, BBIdx);

      {
        bool success = b.bbbmap.emplace(Addr, BBIdx);
        assert(success);
      }
#if 0
      llvm::errs() << "         BBIdx=" << BBIdx
		   << " intervl=" << addr_intvl2str(intervl) << '\n';
#endif
    }
  }

  {
    //
    // a new basic block has been created
    //
    if (unlikely(this->verbose))
      llvm::errs() << llvm::formatv("{0} {1}\n",
				    description_of_block(ICFG[bb], false),
				    description_of_terminator_info(T, false));

    this->on_newbb_proc(b, bb);
  }

  {
    ip_scoped_lock<ip_mutex> e_lck(b.na_bbmap_mtx);

    b.bbmap_na = false;
    b.na_cond.notify_one();
  }

  auto control_flow_to = [&](uint64_t Target) -> void {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    Target &= ~1UL;
#endif

    _control_flow_to(b, Bin, T.Addr ?: Addr, Target, process_later);
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
    {
      ip_sharable_lock<ip_upgradable_mutex> s_lck(b.bbmap_mtx);

      basic_block_t bb = basic_block_at_address(T.Addr, b);
      ICFG[bb].Term._call.ReturnsOff = T._call.NextPC - T.Addr;
    }

    uint64_t CalleeAddr = T._call.Target;

#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
    CalleeAddr &= ~1UL;
#endif

    function_index_t CalleeFIdx = _explore_function(b, Bin, CalleeAddr,
                                                    process_later);
    {
      ip_sharable_lock<ip_upgradable_mutex> s_lck(b.bbmap_mtx);

      basic_block_t bb = basic_block_at_address(T.Addr, b);
      assert(ICFG[bb].Term.Type == TERMINATOR::CALL);

      ICFG[bb].Term._call.Target = CalleeFIdx;
    }

    if (!is_function_index_valid(CalleeFIdx)) {
      llvm::WithColor::warning() << llvm::formatv(
          "explore_basic_block: invalid call @ {0:x}\n", T.Addr);
      break;
    }

    basic_block_index_t CalleeIdx = b.Analysis.Functions.at(CalleeFIdx).Entry;

    if (!is_basic_block_index_valid(CalleeIdx)) {
      process_later(later_item_t(T.Addr, CalleeAddr));
      break;
    }

    bool DoesRet = ({
      ip_sharable_lock<ip_upgradable_mutex> s_lck(b.bbmap_mtx);

      does_function_at_block_return(basic_block_of_index(CalleeIdx, ICFG), b);
    });

    if (DoesRet)
      control_flow_to(T._call.NextPC);

    break;
  }

  case TERMINATOR::INDIRECT_CALL: {
    basic_block_t bb = ({
      ip_sharable_lock<ip_upgradable_mutex> s_lck(b.bbmap_mtx);

      basic_block_at_address(T.Addr, b);
    });

    ICFG[bb].Term._indirect_call.ReturnsOff = T._indirect_call.NextPC - T.Addr;

    //control_flow_to(T._indirect_call.NextPC);
    break;
  }

  case TERMINATOR::INDIRECT_JUMP:
  case TERMINATOR::RETURN:
  case TERMINATOR::UNREACHABLE:
    break;

  case TERMINATOR::NONE:
    control_flow_to(T._none.NextPC);
    break;

  case TERMINATOR::UNKNOWN:
  default:
    throw std::runtime_error((fmt("%s: unknown terminator @ 0x%lx") % __func__ % T.Addr).str());
  }

  return BBIdx;
}

void explorer_t::_control_flow_to(binary_t &b,
                                  obj::Binary &Bin,
                                  const uint64_t TermAddr,
                                  const uint64_t Target,
                                  process_later_t process_later) {
  assert(Target);

  if (unlikely(this->verbose))
    llvm::errs() << llvm::formatv("  -> {0}\n",
                                  taddr2str(Target, false));

  basic_block_index_t SuccBBIdx =
      _explore_basic_block(b, Bin, Target, process_later);

  assert(is_basic_block_index_valid(SuccBBIdx));

  {
    ip_upgradable_lock<ip_upgradable_mutex> u_lck(b.bbmap_mtx);

    auto &ICFG = b.Analysis.ICFG;

    basic_block_t bb = basic_block_at_address(TermAddr, b);
    // assert(T.Type == ICFG[bb].Term.Type);

    ip_scoped_lock<ip_upgradable_mutex> e_lck(boost::move(u_lck));

    bool isNewTarget =
        boost::add_edge(bb, basic_block_of_index(SuccBBIdx, b), ICFG).second;
    (void)isNewTarget;
  }
}

void explorer_t::_explore_the_rest(binary_t &b,
                                   obj::Binary & B,
                                   const std::vector<later_item_t> &calls_to_process) {
  auto DoBody = [&](const later_item_t &x,
                    oneapi::tbb::feeder<later_item_t> &feeder) {
    auto process_later = [&](later_item_t &&later) -> void {
      feeder.add(std::move(later));
    };

    uint64_t TermAddr;
    uint64_t CalleeAddr;
    std::tie(TermAddr, CalleeAddr) = x;

    const function_index_t CalleeFIdx =
        _explore_function(b, B, CalleeAddr, process_later);
    assert(is_function_index_valid(CalleeFIdx));

    basic_block_index_t &CalleeIdx = b.Analysis.Functions.at(CalleeFIdx).Entry;
    if (unlikely(!is_basic_block_index_valid(CalleeIdx))) { /* XXX how? */
      CalleeIdx = _explore_basic_block(b, B, CalleeAddr, process_later);
      assert(is_basic_block_index_valid(CalleeIdx));
    }

    unsigned RetOff;

    auto &ICFG = b.Analysis.ICFG;
    bool DoesRet = ({
      ip_sharable_lock<ip_upgradable_mutex> s_lck(b.bbmap_mtx);

      RetOff = ICFG[basic_block_at_address(TermAddr, b)].Term._call.ReturnsOff;

      does_function_at_block_return(basic_block_of_index(CalleeIdx, ICFG), b);
    });

    if (DoesRet)
      _control_flow_to(b, B,
                       TermAddr,
                       TermAddr + RetOff,
                       process_later);
  };

  oneapi::tbb::parallel_for_each(calls_to_process.begin(),
                                 calls_to_process.end(), DoBody);
}

basic_block_index_t explorer_t::explore_basic_block(binary_t &b,
                                                    obj::Binary &B,
                                                    uint64_t Addr) {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  Addr &= ~1UL;
#endif

  std::vector<later_item_t> calls_to_process;

  const basic_block_index_t res =
      _explore_basic_block(b, B, Addr, [&](later_item_t &&item) {
        calls_to_process.push_back(std::move(item));
      });

  _explore_the_rest(b, B, calls_to_process);

  return res;
}

function_index_t explorer_t::explore_function(binary_t &b,
                                              obj::Binary &B,
                                              uint64_t Addr) {
#if defined(TARGET_MIPS64) || defined(TARGET_MIPS32)
  Addr &= ~1UL;
#endif

  std::vector<later_item_t> calls_to_process;

  const function_index_t res =
      _explore_function(b, B, Addr, [&](later_item_t &&item) {
        calls_to_process.push_back(std::move(item));
      });

  _explore_the_rest(b, B, calls_to_process);

  return res;
}

}
