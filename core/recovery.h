#pragma once
#include "jove/jove.h"
#include "disas.h"
#include "B.h"
#include "symbolizer.h"

namespace jove {

template <bool MT, bool MinSize>
class explorer_t;

template <bool MT, bool MinSize>
class CodeRecovery {
  using jv_t = jv_base_t<MT, MinSize>;
  using binary_t = binary_base_t<MT, MinSize>;

  using bb_t = binary_t::bb_t;

  jv_file_t &jv_file;
  jv_t &jv;

  explorer_t<MT, MinSize> &E;

  symbolizer_t &symbolizer;

  struct binary_state_t {
    std::unique_ptr<llvm::object::Binary> Bin;

    binary_state_t(const binary_t &b) { Bin = B::Create(b.data()); }
  };

  jv_state_t<binary_state_t, void, void, AreWeMT, true, false, true, true, MT,
             MinSize>
      state;

public:
  CodeRecovery(jv_file_t &, jv_t &, explorer_t<MT, MinSize> &E, symbolizer_t &);
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
