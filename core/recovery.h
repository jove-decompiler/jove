#pragma once
#include <jove/jove.h>
#include "explore.h"

namespace jove {

class CodeRecovery {
  decompilation_t &decompilation;

  tiny_code_generator_t tcg;
  disas_t dis;

  struct binary_state_t {
    std::vector<tcg_uintptr_t> block_term_addr_vec;

    bbmap_t bbmap;
    fnmap_t fnmap;

    std::unique_ptr<llvm::object::Binary> ObjectFile;
  };

  std::vector<binary_state_t> bin_state_vec;

  std::string DescribeFunction(binary_index_t, function_index_t);
  std::string DescribeBasicBlock(binary_index_t, basic_block_index_t);

public:
  CodeRecovery(decompilation_t &, disas_t);

  std::string RecoverDynamicTarget(uint32_t CallerBIdx,
                                   uint32_t CallerBBIdx,
                                   uint32_t CalleeBIdx,
                                   uint32_t CalleeFIdx);

  std::string RecoverBasicBlock(uint32_t IndBrBIdx,
                                uint32_t IndBrBBIdx,
                                tcg_uintptr_t Addr);

  std::string RecoverFunction(uint32_t IndCallBIdx,
                              uint32_t IndCallBBIdx,
                              uint32_t CalleeBIdx,
                              tcg_uintptr_t CalleeAddr);

  std::string RecoverABI(uint32_t BIdx,
                         uint32_t FIdx);

  std::string Returns(uint32_t CallBIdx,
                      uint32_t CallBBIdx);
};

}
