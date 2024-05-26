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
  for_each_binary(jv, [&](binary_t &binary) {
    binary_state_t &binary_state = state.for_binary(binary);

    auto &ICFG = binary.Analysis.ICFG;

    binary_state.block_term_addr_vec.resize(boost::num_vertices(ICFG));

    //
    // we need to record the addresses of terminator instructions at each
    // basic block, before the indices are messed with, since the code in
    // jove.recover.c is hard-coded against the version of the jv
    // that existed when jove-recompile was run.
    //
    for_each_basic_block_in_binary(binary, [&](basic_block_t bb) {
      binary_state.block_term_addr_vec.at(index_of_basic_block(ICFG, bb)) = ICFG[bb].Term.Addr;
    });

    ignore_exception([&]() {
      binary_state.ObjectFile = CreateBinary(binary.data());
    });
  });
}

CodeRecovery::~CodeRecovery() {}

uint64_t CodeRecovery::AddressOfTerminatorAtBasicBlock(uint32_t BIdx,
                                                            uint32_t BBIdx) {
  binary_t &binary = jv.Binaries.at(BIdx);
  uint64_t TermAddr =
      state.for_binary(binary).block_term_addr_vec.at(BBIdx);
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

  uint64_t TermAddr = state.for_binary(CallerBinary).block_term_addr_vec.at(CallerBBIdx);
  assert(TermAddr);
  basic_block_t bb = basic_block_at_address(TermAddr, CallerBinary);

  bool isNewTarget = ICFG[bb].insertDynTarget({CalleeBIdx, CalleeFIdx}, jv.Binaries.get_allocator());

  if (!isNewTarget)
    return std::string();

  //
  // check to see if this is an ambiguous indirect jump XXX duplicated code with jove-bootstrap
  //
  if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP &&
      IsDefinitelyTailCall(ICFG, bb) &&
      boost::out_degree(bb, ICFG) > 0) {
    //
    // we thought this was a goto, but now we know it's definitely a tail call.
    // translate all sucessors as functions, then store them into the dynamic
    // targets set for this bb. afterwards, delete the edges in the ICFG that
    // would originate from this basic block.
    //
    icfg_t::out_edge_iterator e_it, e_it_end;
    for (std::tie(e_it, e_it_end) = boost::out_edges(bb, ICFG);
         e_it != e_it_end; ++e_it) {
      control_flow_t cf(*e_it);

      basic_block_t succ = boost::target(cf, ICFG);

      function_index_t FIdx =
          E.explore_function(CallerBinary, *state.for_binary(CallerBinary).ObjectFile,
                             ICFG[succ].Addr);
      assert(is_function_index_valid(FIdx));

      /* term bb may been split */
      bb = basic_block_at_address(TermAddr, CallerBinary);
      ICFG[bb].insertDynTarget({CallerBIdx, FIdx}, jv.Binaries.get_allocator());
    }

    boost::clear_out_edges(bb, ICFG);
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

  return (fmt(__ANSI_CYAN "(call) %s -> %s" __ANSI_NORMAL_COLOR)
          % symbolizer.addr2desc(CallerBinary, TermAddr)
          % symbolizer.addr2desc(CalleeBinary, entry_address_of_function(callee, CalleeBinary)))
      .str();
}

std::string CodeRecovery::RecoverBasicBlock(uint32_t IndBrBIdx,
                                            uint32_t IndBrBBIdx,
                                            uint64_t Addr) {
  binary_t &indbr_binary = jv.Binaries.at(IndBrBIdx);
  auto &ICFG = indbr_binary.Analysis.ICFG;

  uint64_t TermAddr =
      state.for_binary(indbr_binary).block_term_addr_vec.at(IndBrBBIdx);
  assert(TermAddr);

  basic_block_t bb = basic_block_at_address(TermAddr, indbr_binary);

  assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);
  basic_block_index_t target_bb_idx = E.explore_basic_block(
      indbr_binary, *state.for_binary(indbr_binary).ObjectFile, Addr);
  if (!is_basic_block_index_valid(target_bb_idx)) {
    throw std::runtime_error(
        (fmt("failed to recover control flow to %#lx") % Addr).str());
  }

  basic_block_t target_bb = basic_block_of_index(target_bb_idx, ICFG);

  /* term bb may been split */
  bb = basic_block_at_address(TermAddr, indbr_binary);

  assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

  bool isNewTarget = boost::add_edge(bb, target_bb, ICFG).second;
  if (!isNewTarget)
    return std::string();

  return (fmt(__ANSI_GREEN "(goto) %s -> %s" __ANSI_NORMAL_COLOR)
          % symbolizer.addr2desc(indbr_binary, TermAddr)
          % symbolizer.addr2desc(indbr_binary, Addr))
      .str();
}

std::string CodeRecovery::RecoverFunction(uint32_t IndCallBIdx,
                                          uint32_t IndCallBBIdx,
                                          uint32_t CalleeBIdx,
                                          uint64_t CalleeAddr) {
  binary_t &CalleeBinary = jv.Binaries.at(CalleeBIdx);
  binary_t &CallerBinary = jv.Binaries.at(IndCallBIdx);

  auto &ICFG = CallerBinary.Analysis.ICFG;
  uint64_t TermAddr =
      state.for_binary(CallerBinary).block_term_addr_vec.at(IndCallBBIdx);
  assert(TermAddr);

  basic_block_t bb = basic_block_at_address(TermAddr, CallerBinary);

  function_index_t CalleeFIdx = E.explore_function(
      CalleeBinary, *state.for_binary(CalleeBinary).ObjectFile, CalleeAddr);
  if (!is_function_index_valid(CalleeFIdx)) {
    throw std::runtime_error(
        (fmt("failed to translate indirect call target %#lx") % CalleeAddr)
            .str());
  }

  function_t &callee = CalleeBinary.Analysis.Functions.at(CalleeFIdx);

  /* term bb may been split */
  bb = basic_block_at_address(TermAddr, CallerBinary);

  bool isNewTarget = ICFG[bb].insertDynTarget({CalleeBIdx, CalleeFIdx}, jv.Binaries.get_allocator());
  (void)isNewTarget; /* FIXME */

  if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP)
    assert(boost::out_degree(bb, ICFG) == 0);

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
  binary_t &CallBinary = jv.Binaries.at(CallBIdx);
  auto &ICFG = CallBinary.Analysis.ICFG;

  uint64_t TermAddr = state.for_binary(CallBinary).block_term_addr_vec.at(CallBBIdx);
  assert(TermAddr);

  basic_block_t bb = basic_block_at_address(TermAddr, CallBinary);

  uint64_t NextAddr = ICFG[bb].Addr + ICFG[bb].Size + (unsigned)IsMIPSTarget * 4;

  bool isCall =
    ICFG[bb].Term.Type == TERMINATOR::CALL;
  bool isIndirectCall =
    ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL;

  assert(isCall || isIndirectCall);
  assert(TermAddr);

  if (isCall)
    ICFG[bb].Term._call.Returns = true;
  if (isIndirectCall)
    ICFG[bb].Term._indirect_call.Returns = true;

  unsigned deg = boost::out_degree(bb, ICFG);
  if (deg != 0) {
    return std::string();
  }

  basic_block_index_t next_bb_idx =
    E.explore_basic_block(CallBinary, *state.for_binary(CallBinary).ObjectFile, NextAddr);

  /* term bb may been split */
  bb = basic_block_at_address(TermAddr, CallBinary);

  if (ICFG[bb].Term.Type == TERMINATOR::CALL &&
      is_function_index_valid(ICFG[bb].Term._call.Target)) {
    function_t &f = CallBinary.Analysis.Functions.at(ICFG[bb].Term._call.Target);
    f.Returns = true;
  }

  assert(is_basic_block_index_valid(next_bb_idx));
  basic_block_t next_bb = basic_block_of_index(next_bb_idx, ICFG);

  bool isNewTarget = boost::add_edge(bb, next_bb, ICFG).second;
  (void)isNewTarget; /* FIXME */

  return (fmt(__ANSI_YELLOW "(returned) %s" __ANSI_NORMAL_COLOR)
          % symbolizer.addr2desc(CallBinary, NextAddr))
      .str();
}

}
