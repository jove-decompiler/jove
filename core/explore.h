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

struct invalid_control_flow_exception {
  std::string name_of_binary;
  taddr_t pc = ~0UL;

  invalid_control_flow_exception() = default;
  template <bool MT>
  invalid_control_flow_exception(binary_base_t<MT> &b, uint64_t pc)
      : name_of_binary(b.Name.c_str()), pc(pc) {}
};

struct tiny_code_generator_t;

typedef std::function<void(basic_block_t, basic_block_properties_t &)> onblockproc_t;
typedef std::function<void(basic_block_index_t)> onblockproc_u_t;


template <bool MT>
using on_newbb_proc_t = std::function<void(binary_base_t<MT> &, basic_block_t)>;

template <bool MT>
using on_newfn_proc_t = std::function<void(binary_base_t<MT> &, function_t &)>;

static inline void nop_on_block(basic_block_t,
                                basic_block_properties_t &) {}
static inline void nop_on_block_u(basic_block_index_t) {}

//
// performs accurate recursive traversal disassembly
//
template <bool MT>
class explorer_t {
  friend explorer_t<false>;
  friend explorer_t<true>;

  boost::optional<jv_base_t<MT> &> maybe_jv;
  disas_t &disas;
  tiny_code_generator_t &tcg;
  const unsigned VerbosityLevel;

  on_newbb_proc_t<MT> on_newbb_proc = [](binary_base_t<MT> &, basic_block_t) {};
  on_newfn_proc_t<MT> on_newfn_proc = [](binary_base_t<MT> &, function_t &) {};

  template <bool WithOnBlockProc>
  bool split(binary_base_t<MT> &, llvm::object::Binary &,
             bbprop_t::exclusive_lock_guard<MT> e_lck_bb,
             bbmap_t::iterator it,
             const taddr_t Addr,
             basic_block_index_t,
             onblockproc_t obp = nop_on_block);

  template <bool WithOnBlockProc>
  basic_block_index_t _explore_basic_block(
      binary_base_t<MT> &,
      llvm::object::Binary &,
      const taddr_t Addr,
      bool Speculative,
      const function_index_t ParentIdx = invalid_function_index,
      onblockproc_t obp = nop_on_block,
      onblockproc_u_t obp_u = nop_on_block_u);

  function_index_t _explore_function(binary_base_t<MT> &,
                                     llvm::object::Binary &,
                                     const taddr_t Addr,
                                     const bool Speculative);

  void _control_flow_to(binary_base_t<MT> &,
                        llvm::object::Binary &,
                        const taddr_t TermAddr,
                        const taddr_t Target,
                        const bool Speculative,
                        basic_block_t bb /* unused if !Speculative */);

  bool IsVerbose(void) const { return unlikely(VerbosityLevel >= 1); }
  bool IsVeryVerbose(void) const { return unlikely(VerbosityLevel >= 2); }

public:
  explorer_t(jv_base_t<MT> &jv, disas_t &disas, tiny_code_generator_t &tcg,
             unsigned VerbosityLevel = 0)
      : maybe_jv(jv), disas(disas), tcg(tcg), VerbosityLevel(VerbosityLevel) {}

  explorer_t(disas_t &disas, tiny_code_generator_t &tcg,
             unsigned VerbosityLevel = 0)
      : maybe_jv(boost::none), disas(disas), tcg(tcg), VerbosityLevel(VerbosityLevel) {}

  template <bool MT2>
  explorer_t(const explorer_t<MT2> &other)
      : maybe_jv(boost::none),
        disas(other.disas),
        tcg(other.tcg),
        VerbosityLevel(other.VerbosityLevel) {
     assert(!other.on_newbb_proc);
     assert(!other.on_newfn_proc);
  }

  //
  // the objective is to translate all the code we can up until indirect
  // control-flow instructions. this is precisely what jove-bootstrap needs to
  // do when it sees new code before it can allow the tracee to continue
  // executing.
  //
  basic_block_index_t explore_basic_block(binary_base_t<MT> &,
                                          llvm::object::Binary &,
                                          taddr_t Addr);

  basic_block_index_t explore_basic_block(binary_base_t<MT> &,
                                          llvm::object::Binary &,
                                          taddr_t Addr,
                                          onblockproc_t obp,
                                          onblockproc_u_t obp_u);

  function_index_t explore_function(binary_base_t<MT> &,
                                    llvm::object::Binary &,
                                    taddr_t Addr);

  on_newbb_proc_t<MT> get_newbb_proc(void) const { return on_newbb_proc; }
  void set_newbb_proc(on_newbb_proc_t<MT> proc) { on_newbb_proc = proc; }

  // NOTE: the new function will initially posses an invalid basic block index
  // for Entry
  on_newfn_proc_t<MT> get_newfn_proc(void) const { return on_newfn_proc; }
  void set_newfn_proc(on_newfn_proc_t<MT> proc) { on_newfn_proc = proc; }

  boost::optional<jv_base_t<MT> &> get_jv(void) const {
    return maybe_jv;
  }
};

}
