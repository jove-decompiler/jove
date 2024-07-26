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
    std::vector<uint64_t> block_term_addr_vec;

    std::unique_ptr<llvm::object::Binary> ObjectFile;
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

  std::string RecoverFunction(binary_index_t IndCallBIdx,
                              basic_block_index_t IndCallBBIdx,
                              binary_index_t CalleeBIdx,
                              uint64_t CalleeAddr);

  std::string RecoverABI(binary_index_t BIdx,
                         function_index_t FIdx);

  std::string Returns(binary_index_t CallBIdx,
                      basic_block_index_t CallBBIdx);
};

}
