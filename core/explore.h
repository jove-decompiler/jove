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
typedef std::function<void(binary_t &, function_t &)> on_newfn_proc_t;

class explorer_t {
  jv_t &jv;
  disas_t &disas;
  tiny_code_generator_t &tcg;
  const bool verbose;

  on_newbb_proc_t on_newbb_proc;
  on_newfn_proc_t on_newfn_proc;

  typedef std::pair<uint64_t, uint64_t> later_item_t;
  typedef std::function<void(later_item_t &&)> process_later_t;

  basic_block_index_t _explore_basic_block(binary_t &,
                                           llvm::object::Binary &,
                                           const uint64_t Addr,
                                           process_later_t process_later);

  function_index_t _explore_function(binary_t &,
                                     llvm::object::Binary &,
                                     const uint64_t Addr,
                                     process_later_t process_later);

  void _explore_the_rest(binary_t &,
                         llvm::object::Binary &,
                         const std::vector<later_item_t> &calls_to_process);

  void _control_flow_to(binary_t &,
                        llvm::object::Binary &,
                        const uint64_t TermAddr,
                        const uint64_t Target,
                        process_later_t process_later);

public:
  explorer_t(
      jv_t &jv, disas_t &disas, tiny_code_generator_t &tcg,
      bool verbose = false,
      on_newbb_proc_t on_newbb_proc = [](binary_t &, basic_block_t) {},
      on_newfn_proc_t on_newfn_proc = [](binary_t &, function_t &) {})
      : jv(jv), disas(disas), tcg(tcg), verbose(verbose),
        on_newbb_proc(on_newbb_proc),
        on_newfn_proc(on_newfn_proc) {}

  //
  // the objective is to translate all the code we can up until indirect
  // control-flow instructions. this is precisely what jove-bootstrap needs to
  // do when it sees new code before it can allow the tracee to continue
  // executing.
  //
  basic_block_index_t explore_basic_block(binary_t &,
                                          llvm::object::Binary &,
                                          uint64_t Addr);

  function_index_t explore_function(binary_t &,
                                    llvm::object::Binary &,
                                    uint64_t Addr);

  on_newbb_proc_t get_newbb_proc(void) const {
    return on_newbb_proc;
  }

  void set_newbb_proc(on_newbb_proc_t proc) {
    on_newbb_proc = proc;
  }

  on_newfn_proc_t get_newfn_proc(void) const {
    return on_newfn_proc;
  }

  // NOTE: the new function will initially posses an invalid basic block index
  // for Entry
  void set_newfn_proc(on_newfn_proc_t proc) {
    on_newfn_proc = proc;
  }
};

}
