#include "recovery.h"
#include "util.h"
#include "explore.h"

#include <stdexcept>

#include <llvm/Support/FormatVariadic.h>

#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include "jove_macros.h"

namespace obj = llvm::object;
namespace fs = boost::filesystem;

namespace jove {

typedef boost::format fmt;

CodeRecovery::CodeRecovery(jv_t &jv, explorer_t &E, symbolizer_t &symbolizer)
    : jv(jv), E(E), symbolizer(symbolizer), state(jv) {
  for_each_binary(std::execution::par_unseq, jv, [&](binary_t &binary) {
    binary_state_t &x = state.for_binary(binary);

    auto &ICFG = binary.Analysis.ICFG;
    x.block_term_addr_vec.resize(boost::num_vertices(ICFG));

    //
    // FIXME we need to record the addresses of terminator instructions at each
    // basic block, before the indices are messed with, since the code in
    // jove.recover.c is hard-coded against the version of the jv
    // that existed when jove-recompile was run.
    //
    for_each_basic_block_in_binary(std::execution::par_unseq,
                                   binary, [&](basic_block_t bb) {
      x.block_term_addr_vec.at(index_of_basic_block(ICFG, bb)) = ICFG[bb].Term.Addr;
    });

    x.ObjectFile = B::Create(binary.data());
  });
}

CodeRecovery::~CodeRecovery() {}

uint64_t CodeRecovery::AddressOfTerminatorAtBasicBlock(uint32_t BIdx,
                                                       uint32_t BBIdx) {
  binary_t &binary = jv.Binaries.at(BIdx);
  uint64_t TermAddr = state.for_binary(binary).block_term_addr_vec.at(BBIdx);
  assert(TermAddr);
  return TermAddr;
}

std::string CodeRecovery::RecoverDynamicTarget(uint32_t CallerBIdx,
                                               uint32_t CallerBBIdx,
                                               uint32_t CalleeBIdx,
                                               uint32_t CalleeFIdx) {
  binary_t &CallerBinary = jv.Binaries.at(CallerBIdx);
  binary_t &CalleeBinary = jv.Binaries.at(CalleeBIdx);

  function_t &callee = CalleeBinary.Analysis.Functions.at(CalleeFIdx);
  assert(is_basic_block_index_valid(callee.Entry));

  auto &ICFG = CallerBinary.Analysis.ICFG;

  uint64_t TermAddr = AddressOfTerminatorAtBasicBlock(CallerBIdx, CallerBBIdx);
  assert(TermAddr);

  bool Ambig = ({
    ip_upgradable_lock<ip_upgradable_mutex> u_lck(CallerBinary.bbmap_mtx);

    basic_block_t bb = basic_block_at_address(TermAddr, CallerBinary);

    ip_scoped_lock<ip_upgradable_mutex> e_lck(boost::move(u_lck));

    bool isNewTarget = ICFG[bb].insertDynTarget({CalleeBIdx, CalleeFIdx}, jv);
    if (!isNewTarget)
      return std::string();

    ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP &&
    IsDefinitelyTailCall(ICFG, bb) &&
    boost::out_degree(bb, ICFG) > 0;
  });

  //
  // check to see if this is an ambiguous indirect jump XXX duplicated code with jove-bootstrap
  //
  if (Ambig) {
    //
    // we thought this was a goto, but now we know it's definitely a tail call.
    // translate all sucessors as functions, then store them into the dynamic
    // targets set for this bb. afterwards, delete the edges in the ICFG that
    // would originate from this basic block.
    //
    std::vector<taddr_t> succ_addr_vec;

    {
      ip_upgradable_lock<ip_upgradable_mutex> u_lck(CallerBinary.bbmap_mtx);

      basic_block_t bb = basic_block_at_address(TermAddr, CallerBinary);

      succ_addr_vec.reserve(boost::out_degree(bb, ICFG));

      icfg_t::adjacency_iterator succ_it, succ_it_end;
      for (std::tie(succ_it, succ_it_end) = boost::adjacent_vertices(bb, ICFG);
           succ_it != succ_it_end; ++succ_it)
        succ_addr_vec.push_back(ICFG[*succ_it].Addr);

      ip_scoped_lock<ip_upgradable_mutex> e_lck(boost::move(u_lck));

      boost::clear_out_edges(bb, ICFG);
    }

    for (const taddr_t &addr : succ_addr_vec) {
      function_index_t FIdx = E.explore_function(
          CallerBinary, *state.for_binary(CallerBinary).ObjectFile, addr);

      assert(is_function_index_valid(FIdx));

      {
        ip_upgradable_lock<ip_upgradable_mutex> u_lck(CallerBinary.bbmap_mtx);

        basic_block_t bb = basic_block_at_address(TermAddr, CallerBinary);

        ip_scoped_lock<ip_upgradable_mutex> e_lck(boost::move(u_lck));

        ICFG[bb].insertDynTarget({CallerBIdx, FIdx}, jv);
      }
    }

#if 0
  } else if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL &&
             isNewTarget &&
             boost::out_degree(bb, ICFG) == 0 &&
             does_function_return(callee, CalleeBinary)) {
    //
    // this call instruction will return, so explore the return block
    //
    basic_block_index_t NextBBIdx =
        E.explore_basic_block(CallerBinary, *state.for_binary(CallerBinary).ObjectFile,
                              ICFG[bb].Addr + ICFG[bb].Size + IsMIPSTarget * 4);

    assert(is_basic_block_index_valid(NextBBIdx));

    /* term bb may been split */
    bb = basic_block_at_address(TermAddr, CallerBinary);
    assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL);

    boost::add_edge(bb, basic_block_of_index(NextBBIdx, ICFG), ICFG);
  }
#else
  }
#endif

  return (fmt(__ANSI_CYAN "(call) %s -> %s" __ANSI_NORMAL_COLOR)
          % symbolizer.addr2desc(CallerBinary, TermAddr)
          % symbolizer.addr2desc(CalleeBinary, entry_address_of_function(callee, CalleeBinary)))
      .str();
}

std::string CodeRecovery::RecoverBasicBlock(uint32_t IndBrBIdx,
                                            uint32_t IndBrBBIdx,
                                            uint64_t Addr) {
  binary_t &b = jv.Binaries.at(IndBrBIdx);
  auto &ICFG = b.Analysis.ICFG;

  basic_block_index_t TargetBBIdx =
      E.explore_basic_block(b, *state.for_binary(b).ObjectFile, Addr);
  if (!is_basic_block_index_valid(TargetBBIdx)) {
    throw std::runtime_error(
        (fmt("failed to recover control flow to %#lx") % Addr).str());
  }

  uint64_t TermAddr = AddressOfTerminatorAtBasicBlock(IndBrBIdx, IndBrBBIdx);

  bool isNewTarget = ({
    ip_upgradable_lock<ip_upgradable_mutex> u_lck(b.bbmap_mtx);

    basic_block_t bb = basic_block_at_address(TermAddr, b);
    assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

    ip_scoped_lock<ip_upgradable_mutex> e_lck(boost::move(u_lck));

    basic_block_t target_bb = basic_block_of_index(TargetBBIdx, ICFG);
    boost::add_edge(bb, target_bb, ICFG).second;
  });

  if (!isNewTarget)
    return std::string();

  return (fmt(__ANSI_GREEN "(goto) %s -> %s" __ANSI_NORMAL_COLOR)
          % symbolizer.addr2desc(b, TermAddr)
          % symbolizer.addr2desc(b, Addr))
      .str();
}

std::string CodeRecovery::RecoverFunction(uint32_t IndCallBIdx,
                                          uint32_t IndCallBBIdx,
                                          uint32_t CalleeBIdx,
                                          uint64_t CalleeAddr) {
  binary_t &CalleeBinary = jv.Binaries.at(CalleeBIdx);

  function_index_t CalleeFIdx = E.explore_function(
      CalleeBinary, *state.for_binary(CalleeBinary).ObjectFile, CalleeAddr);
  if (!is_function_index_valid(CalleeFIdx))
    throw std::runtime_error((fmt("failed to translate indirect call target %#lx") % CalleeAddr).str());

  binary_t &CallerBinary = jv.Binaries.at(IndCallBIdx);
  uint64_t TermAddr = AddressOfTerminatorAtBasicBlock(IndCallBIdx, IndCallBBIdx);

  function_t &callee = CalleeBinary.Analysis.Functions.at(CalleeFIdx);

  auto &ICFG = CallerBinary.Analysis.ICFG;

  bool isNewTarget = ({
    ip_upgradable_lock<ip_upgradable_mutex> u_lck(CallerBinary.bbmap_mtx);

    basic_block_t bb = basic_block_at_address(TermAddr, CallerBinary);

    if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP)
      assert(boost::out_degree(bb, ICFG) == 0);

    ip_scoped_lock<ip_upgradable_mutex> e_lck(boost::move(u_lck));

    ICFG[bb].insertDynTarget({CalleeBIdx, CalleeFIdx}, jv);
  });

  (void)isNewTarget; /* FIXME */

#if 0
  if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL &&
      does_function_return(callee, CalleeBinary)) {
    //
    // this call instruction will return, so explore the return block
    //
    basic_block_index_t NextBBIdx =
        E.explore_basic_block(CallerBinary, *state.for_binary(CallerBinary).ObjectFile,
                              ICFG[bb].Addr + ICFG[bb].Size + IsMIPSTarget * 4);

    assert(is_basic_block_index_valid(NextBBIdx));

    /* term bb may been split */
    bb = basic_block_at_address(TermAddr, CallerBinary);
    assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL);

    boost::add_edge(bb, basic_block_of_index(NextBBIdx, ICFG), ICFG);
  }
#endif

  return (fmt(__ANSI_CYAN "(call*) %s -> %s" __ANSI_NORMAL_COLOR)
          % symbolizer.addr2desc(CallerBinary, TermAddr)
          % symbolizer.addr2desc(CalleeBinary, CalleeAddr))
      .str();
}

std::string CodeRecovery::RecoverABI(uint32_t BIdx,
                                     uint32_t FIdx) {
  dynamic_target_t NewABI(BIdx, FIdx);

  function_t &f = function_of_target(NewABI, jv);

  if (f.IsABI)
    return std::string(); // given function already marked as an ABI

  f.IsABI = true;

  return (fmt(__ANSI_BLUE "(abi) %s" __ANSI_NORMAL_COLOR)
          % symbolizer.addr2desc(jv.Binaries.at(NewABI.first), entry_address_of_function(f, jv.Binaries.at(NewABI.first))))
      .str();
}

std::string CodeRecovery::Returns(uint32_t CallBIdx,
                                  uint32_t CallBBIdx) {
  binary_t &b = jv.Binaries.at(CallBIdx);
  auto &ICFG = b.Analysis.ICFG;

  uint64_t TermAddr = AddressOfTerminatorAtBasicBlock(CallBIdx, CallBBIdx);

  uint64_t NextAddr = ({
    ip_sharable_lock<ip_upgradable_mutex> s_lck(b.bbmap_mtx);

    basic_block_t bb = basic_block_at_address(TermAddr, b);

    ICFG[bb].Addr + ICFG[bb].Size + (unsigned)IsMIPSTarget * 4;
  });

  basic_block_index_t NextBBIdx =
    E.explore_basic_block(b, *state.for_binary(b).ObjectFile, NextAddr);
  assert(is_basic_block_index_valid(NextBBIdx));

  bool isNewTarget = ({
    ip_upgradable_lock<ip_upgradable_mutex> u_lck(b.bbmap_mtx);

    basic_block_t bb = basic_block_at_address(TermAddr, b);

    bool isCall = ICFG[bb].Term.Type == TERMINATOR::CALL;
    bool isIndirectCall = ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL;

    assert(isCall || isIndirectCall);
    assert(TermAddr);

    if (isCall)
      ICFG[bb].Term._call.Returns = true;
    if (isIndirectCall)
      ICFG[bb].Term._indirect_call.Returns = true;

    if (ICFG[bb].Term.Type == TERMINATOR::CALL &&
        is_function_index_valid(ICFG[bb].Term._call.Target)) {
      function_t &f = b.Analysis.Functions.at(ICFG[bb].Term._call.Target);
      f.Returns = true;
    }

    ip_scoped_lock<ip_upgradable_mutex> e_lck(boost::move(u_lck));

    unsigned deg = boost::out_degree(bb, ICFG);
    if (deg > 0)
      return std::string();

    boost::add_edge(bb, basic_block_of_index(NextBBIdx, ICFG), ICFG).second;
  });

  (void)isNewTarget; /* FIXME */

  return (fmt(__ANSI_YELLOW "(returned) %s" __ANSI_NORMAL_COLOR)
          % symbolizer.addr2desc(b, NextAddr))
      .str();
}

}
