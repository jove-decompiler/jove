#pragma once
#include "jove/jove.h"
#include "disas.h"
#include <functional>

namespace llvm {
namespace object {
class Binary;
}
}

namespace jove {

struct tiny_code_generator_t;

struct explorer_t {
  jv_t &jv;
  disas_t &disas;
  tiny_code_generator_t &tcg;
  const bool verbose;

  explorer_t(jv_t &jv, disas_t &disas, tiny_code_generator_t &tcg, bool verbose = false)
      : jv(jv), disas(disas), tcg(tcg), verbose(verbose) {}

  basic_block_index_t explore_basic_block(binary_t &b,
                                          llvm::object::Binary &B,
                                          const uint64_t Addr,
                                          fnmap_t &,
                                          bbmap_t &,
                                          std::function<void(binary_t &, basic_block_t)> on_newbb_proc = [](binary_t &, basic_block_t){});

  function_index_t explore_function(binary_t &b,
                                    llvm::object::Binary &B,
                                    const uint64_t Addr,
                                    fnmap_t &,
                                    bbmap_t &,
                                    std::function<void(binary_t &, basic_block_t)> on_newbb_proc = [](binary_t &, basic_block_t){});
};

}
