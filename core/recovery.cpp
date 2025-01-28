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

CodeRecovery::CodeRecovery(jv_file_t &jv_file, jv_t &jv,
                           explorer_t &E,
                           symbolizer_t &symbolizer)
    : jv_file(jv_file), jv(jv), E(E), symbolizer(symbolizer), state(jv) {}

CodeRecovery::~CodeRecovery() {}

uint64_t CodeRecovery::AddressOfTerminatorAtBasicBlock(binary_index_t BIdx,
                                                       basic_block_index_t BBIdx) {
  binary_t &binary = jv.Binaries.at(BIdx);
  uint64_t TermAddr = state.for_binary(binary).block_term_addr_vec.at(BBIdx);
  assert(TermAddr);
  return TermAddr;
}

std::string CodeRecovery::RecoverDynamicTarget(binary_index_t CallerBIdx,
                                               basic_block_index_t CallerBBIdx,
                                               binary_index_t CalleeBIdx,
                                               function_index_t CalleeFIdx) {
  binary_t &CallerBinary = jv.Binaries.at(CallerBIdx);
  binary_t &CalleeBinary = jv.Binaries.at(CalleeBIdx);

  function_t &callee = CalleeBinary.Analysis.Functions.at(CalleeFIdx);
  assert(is_basic_block_index_valid(callee.Entry));

  auto &ICFG = CallerBinary.Analysis.ICFG;

  uint64_t TermAddr = AddressOfTerminatorAtBasicBlock(CallerBIdx, CallerBBIdx);
  assert(TermAddr);

  bool Ambig = ({
    auto s_lck = CallerBinary.BBMap.shared_access();

    basic_block_t bb = basic_block_at_address(TermAddr, CallerBinary);

    bool isNewTarget = ICFG[bb].insertDynTarget(
        CallerBIdx, {CalleeBIdx, CalleeFIdx}, jv_file, jv);
    if (!isNewTarget)
      return std::string();

    ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP &&
    IsAmbiguousIndirectJump(ICFG, bb);
  });

  if (Ambig)
    CallerBinary.FixAmbiguousIndirectJump(
        TermAddr, E, *state.for_binary(CallerBinary).Bin, jv_file, jv);

#if 0
  } else if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL &&
             isNewTarget &&
             ICFG.out_degree(bb) == 0 &&
             does_function_return(callee, CalleeBinary)) {
    //
    // this call instruction will return, so explore the return block
    //
    basic_block_index_t NextBBIdx =
        E.explore_basic_block(CallerBinary, *state.for_binary(CallerBinary).Bin,
                              ICFG[bb].Addr + ICFG[bb].Size + IsMIPSTarget * 4);

    assert(is_basic_block_index_valid(NextBBIdx));

    /* term bb may been split */
    bb = basic_block_at_address(TermAddr, CallerBinary);
    assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL);

    ICFG.add_edge(bb, basic_block_of_index(NextBBIdx, ICFG));
  }
#endif

  return (fmt(__ANSI_CYAN "(call) %s -> %s" __ANSI_NORMAL_COLOR)
          % symbolizer.addr2desc(CallerBinary, TermAddr)
          % symbolizer.addr2desc(CalleeBinary, entry_address_of_function(callee, CalleeBinary)))
      .str();
}

std::string CodeRecovery::RecoverBasicBlock(binary_index_t IndBrBIdx,
                                            basic_block_index_t IndBrBBIdx,
                                            uint64_t Addr) {
  binary_t &b = jv.Binaries.at(IndBrBIdx);
  auto &ICFG = b.Analysis.ICFG;

  basic_block_index_t TargetBBIdx =
      E.explore_basic_block(b, *state.for_binary(b).Bin, Addr);
  if (!is_basic_block_index_valid(TargetBBIdx)) {
    throw std::runtime_error(
        (fmt("failed to recover control flow to %#lx") % Addr).str());
  }

  uint64_t TermAddr = AddressOfTerminatorAtBasicBlock(IndBrBIdx, IndBrBBIdx);

  bool isNewTarget = ({
    auto s_lck = b.BBMap.shared_access();

    basic_block_t bb = basic_block_at_address(TermAddr, b);
    assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP);

    ICFG.add_edge(bb, basic_block_of_index(TargetBBIdx, ICFG)).second;
  });

  if (!isNewTarget)
    return std::string();

  return (fmt(__ANSI_GREEN "(goto) %s -> %s" __ANSI_NORMAL_COLOR)
          % symbolizer.addr2desc(b, TermAddr)
          % symbolizer.addr2desc(b, Addr))
      .str();
}

std::string CodeRecovery::RecoverFunctionAtAddress(binary_index_t IndCallBIdx,
                                                   basic_block_index_t IndCallBBIdx,
                                                   binary_index_t CalleeBIdx,
                                                   uint64_t CalleeAddr) {
  binary_t &CalleeBinary = jv.Binaries.at(CalleeBIdx);

  function_index_t CalleeFIdx = E.explore_function(
      CalleeBinary, *state.for_binary(CalleeBinary).Bin, CalleeAddr);
  if (!is_function_index_valid(CalleeFIdx))
    throw std::runtime_error((fmt("failed to translate indirect call target %#lx") % CalleeAddr).str());

  if (!is_binary_index_valid(IndCallBIdx) ||
      !is_basic_block_index_valid(IndCallBBIdx))
    return (fmt(__ANSI_CYAN "(call*) -> %s" __ANSI_NORMAL_COLOR)
	    % symbolizer.addr2desc(CalleeBinary, CalleeAddr))
	.str();

  binary_t &CallerBinary = jv.Binaries.at(IndCallBIdx);
  uint64_t TermAddr = AddressOfTerminatorAtBasicBlock(IndCallBIdx, IndCallBBIdx);

  auto &ICFG = CallerBinary.Analysis.ICFG;

  bool Ambig = ({
    auto s_lck = CallerBinary.BBMap.shared_access();

    basic_block_t bb = basic_block_at_address(TermAddr, CallerBinary);

    bool isNewTarget = ICFG[bb].insertDynTarget(
        IndCallBIdx, {CalleeBIdx, CalleeFIdx}, jv_file, jv);
    (void)isNewTarget; /* FIXME */

    ICFG[bb].Term.Type == TERMINATOR::INDIRECT_JUMP &&
    IsAmbiguousIndirectJump(ICFG, bb);
  });

  if (Ambig)
    CallerBinary.FixAmbiguousIndirectJump(
        TermAddr, E, *state.for_binary(CallerBinary).Bin, jv_file, jv);

#if 0
  function_t &callee = CalleeBinary.Analysis.Functions.at(CalleeFIdx);
  if (ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL &&
      does_function_return(callee, CalleeBinary)) {
    //
    // this call instruction will return, so explore the return block
    //
    basic_block_index_t NextBBIdx =
        E.explore_basic_block(CallerBinary, *state.for_binary(CallerBinary).Bin,
                              ICFG[bb].Addr + ICFG[bb].Size + IsMIPSTarget * 4);

    assert(is_basic_block_index_valid(NextBBIdx));

    /* term bb may been split */
    bb = basic_block_at_address(TermAddr, CallerBinary);
    assert(ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL);

    ICFG.add_edge(bb, basic_block_of_index(NextBBIdx, ICFG));
  }
#endif

  return (fmt(__ANSI_CYAN "(call*) %s -> %s" __ANSI_NORMAL_COLOR)
          % symbolizer.addr2desc(CallerBinary, TermAddr)
          % symbolizer.addr2desc(CalleeBinary, CalleeAddr))
      .str();
}

std::string CodeRecovery::RecoverFunctionAtOffset(binary_index_t IndCallBIdx,
                                                  basic_block_index_t IndCallBBIdx,
                                                  binary_index_t CalleeBIdx,
                                                  uint64_t CalleeOff) {
  binary_t &CalleeBinary = jv.Binaries.at(CalleeBIdx);

  uint64_t CalleeAddr =
      B::va_of_offset(*state.for_binary(CalleeBinary).Bin, CalleeOff);

  return RecoverFunctionAtAddress(IndCallBIdx, IndCallBBIdx, CalleeBIdx, CalleeAddr);
}

std::string CodeRecovery::RecoverABI(binary_index_t BIdx,
                                     function_index_t FIdx) {
  dynamic_target_t NewABI(BIdx, FIdx);

  function_t &f = function_of_target(NewABI, jv);

  if (f.IsABI)
    return std::string(); // given function already marked as an ABI

  f.IsABI = true;

  return (fmt(__ANSI_BLUE "(abi) %s" __ANSI_NORMAL_COLOR)
          % symbolizer.addr2desc(jv.Binaries.at(NewABI.first), entry_address_of_function(f, jv.Binaries.at(NewABI.first))))
      .str();
}

std::string CodeRecovery::Returns(binary_index_t CallBIdx,
                                  basic_block_index_t CallBBIdx) {
  binary_t &b = jv.Binaries.at(CallBIdx);
  auto &ICFG = b.Analysis.ICFG;

  uint64_t TermAddr = AddressOfTerminatorAtBasicBlock(CallBIdx, CallBBIdx);

  uint64_t NextAddr = ({
    auto s_lck = b.BBMap.shared_access();

    basic_block_t bb = basic_block_at_address(TermAddr, b);

    ICFG[bb].Addr + ICFG[bb].Size + (unsigned)IsMIPSTarget * 4;
  });

  basic_block_index_t NextBBIdx =
      E.explore_basic_block(b, *state.for_binary(b).Bin, NextAddr);
  assert(is_basic_block_index_valid(NextBBIdx));

  bool isNewTarget = ({
    auto s_lck = b.BBMap.shared_access();

    basic_block_t bb = basic_block_at_address(TermAddr, b);

    bool isCall = ICFG[bb].Term.Type == TERMINATOR::CALL;
    bool isIndirectCall = ICFG[bb].Term.Type == TERMINATOR::INDIRECT_CALL;

    assert(isCall || isIndirectCall);
    assert(TermAddr);

    if (isCall && is_function_index_valid(ICFG[bb].Term._call.Target))
      b.Analysis.Functions.at(ICFG[bb].Term._call.Target).Returns = true;

    unsigned deg = ICFG.out_degree(bb);
    if (deg > 0)
      return std::string();

    ICFG.add_edge(bb, basic_block_of_index(NextBBIdx, ICFG)).second;
  });

  (void)isNewTarget; /* FIXME */

  return (fmt(__ANSI_YELLOW "(returned) %s" __ANSI_NORMAL_COLOR)
          % symbolizer.addr2desc(b, NextAddr))
      .str();
}

std::string CodeRecovery::RecoverForeignBinary(const char *path) {
  bool IsNew;
  binary_index_t BIdx;

  std::tie(BIdx, IsNew) = jv.AddFromPath(E, jv_file, path);

  if (!is_binary_index_valid(BIdx) || !IsNew)
    return "";

  return (fmt(__ANSI_BOLD_MAGENTA "(add) \"%s\"" __ANSI_NORMAL_COLOR) % path).str();
}

}
