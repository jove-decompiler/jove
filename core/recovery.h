#pragma once
#include "jove/jove.h"
#include "disas.h"
#include "B.h"
#include "symbolizer.h"

namespace jove {

class explorer_t;

class CodeRecovery {
  jv_t &jv;

  explorer_t &E;

  symbolizer_t &symbolizer;

  struct binary_state_t {
    std::unique_ptr<llvm::object::Binary> Bin;
    std::vector<uint64_t> block_term_addr_vec;

    binary_state_t(const binary_t &b) {
      Bin = B::Create(b.data());

      auto &ICFG = b.Analysis.ICFG;
      block_term_addr_vec.resize(boost::num_vertices(ICFG));

      //
      // FIXME we need to record the addresses of terminator instructions at each
      // basic block, before the indices are messed with, since the code in
      // jove.recover.c is hard-coded against the version of the jv
      // that existed when jove-recompile was run.
      //
      for_each_basic_block_in_binary(std::execution::par_unseq,
                                     b, [&](basic_block_t bb) {
        block_term_addr_vec.at(index_of_basic_block(ICFG, bb)) = ICFG[bb].Term.Addr;
      });
    }
  };

  jv_state_t<binary_state_t, void, void> state;

public:
  CodeRecovery(jv_t &, explorer_t &E, symbolizer_t &);
  ~CodeRecovery();

  uint64_t AddressOfTerminatorAtBasicBlock(binary_index_t BIdx,
                                           basic_block_index_t BBIdx);

  std::string RecoverDynamicTarget(binary_index_t CallerBIdx,
                                   basic_block_index_t CallerBBIdx,
                                   binary_index_t CalleeBIdx,
                                   function_index_t CalleeFIdx);

  std::string RecoverBasicBlock(binary_index_t IndBrBIdx,
                                basic_block_index_t IndBrBBIdx,
                                uint64_t Addr);

  std::string RecoverFunctionAtAddress(binary_index_t IndCallBIdx,
                                       basic_block_index_t IndCallBBIdx,
                                       binary_index_t CalleeBIdx,
                                       uint64_t CalleeAddr);

  std::string RecoverFunctionAtOffset(binary_index_t IndCallBIdx,
                                      basic_block_index_t IndCallBBIdx,
                                      binary_index_t CalleeBIdx,
                                      uint64_t Offset);

  std::string RecoverABI(binary_index_t BIdx,
                         function_index_t FIdx);

  std::string Returns(binary_index_t CallBIdx,
                      basic_block_index_t CallBBIdx);

  std::string RecoverForeignBinary(const char *path);
};

}
