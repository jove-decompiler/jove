#pragma once
#include "disas.h"
#include "explore.h"
#include "symbolizer.h"

namespace jove {

class CodeRecovery {
  jv_t &jv;

  disas_t &disas;
  tiny_code_generator_t &tcg;
  symbolizer_t &symbolizer;

  struct binary_state_t {
    std::vector<uint64_t> block_term_addr_vec;

    bbmap_t bbmap;
    fnmap_t fnmap;

    std::unique_ptr<llvm::object::Binary> ObjectFile;
  };

  jv_bin_state_t<binary_state_t> state;

public:
  CodeRecovery(jv_t &, disas_t &, tiny_code_generator_t &, symbolizer_t &);
  ~CodeRecovery();

  uint64_t AddressOfTerminatorAtBasicBlock(uint32_t BIdx, uint32_t BBIdx);

  std::string RecoverDynamicTarget(uint32_t CallerBIdx,
                                   uint32_t CallerBBIdx,
                                   uint32_t CalleeBIdx,
                                   uint32_t CalleeFIdx);

  std::string RecoverBasicBlock(uint32_t IndBrBIdx,
                                uint32_t IndBrBBIdx,
                                uint64_t Addr);

  std::string RecoverFunction(uint32_t IndCallBIdx,
                              uint32_t IndCallBBIdx,
                              uint32_t CalleeBIdx,
                              uint64_t CalleeAddr);

  std::string RecoverABI(uint32_t BIdx,
                         uint32_t FIdx);

  std::string Returns(uint32_t CallBIdx,
                      uint32_t CallBBIdx);
};

}
