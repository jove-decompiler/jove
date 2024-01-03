#pragma once
#include "jove/jove.h"
#include "disas.h"

#include <functional>
#include <vector>

namespace llvm {
namespace object {
class Binary;
}
}

namespace jove {

struct tiny_code_generator_t;

typedef std::function<void(binary_t &, basic_block_t)> on_newbb_proc_t;

class explorer_t {
  jv_t &jv;
  disas_t &disas;
  tiny_code_generator_t &tcg;
  const bool verbose;

  on_newbb_proc_t on_newbb_proc;

  basic_block_index_t _explore_basic_block(binary_t &,
                                           llvm::object::Binary &,
                                           const uint64_t Addr,
                                           fnmap_t &,
                                           bbmap_t &,
                                           std::vector<uint64_t> &calls_to_process);

  function_index_t _explore_function(binary_t &,
                                     llvm::object::Binary &,
                                     const uint64_t Addr,
                                     fnmap_t &,
                                     bbmap_t &,
                                     std::vector<uint64_t> &calls_to_process);

  void _explore_the_rest(binary_t &,
                         llvm::object::Binary &,
                         fnmap_t &,
                         bbmap_t &,
                         std::vector<uint64_t> &calls_to_process);

  void _control_flow_to(binary_t &,
                        llvm::object::Binary &,
                        fnmap_t &,
                        bbmap_t &,
                        basic_block_t,
                        const uint64_t TermAddr,
                        const uint64_t Target,
                        std::vector<uint64_t> &calls_to_process);

public:
  explorer_t(
      jv_t &jv, disas_t &disas, tiny_code_generator_t &tcg,
      bool verbose = false,
      on_newbb_proc_t on_newbb_proc = [](binary_t &, basic_block_t) {})
      : jv(jv), disas(disas), tcg(tcg), verbose(verbose),
        on_newbb_proc(on_newbb_proc) {}

  basic_block_index_t explore_basic_block(binary_t &,
                                          llvm::object::Binary &,
                                          const uint64_t Addr,
                                          fnmap_t &,
                                          bbmap_t &);

  function_index_t explore_function(binary_t &,
                                    llvm::object::Binary &,
                                    const uint64_t Addr,
                                    fnmap_t &,
                                    bbmap_t &);

  on_newbb_proc_t  get_newbb_proc(void) const {
    return on_newbb_proc;
  }

  void set_newbb_proc(on_newbb_proc_t proc) {
    on_newbb_proc = proc;
  }
};

}
