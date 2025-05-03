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
using on_newbb_proc = std::function<void(binary_base_t<MT> &, basic_block_t)>;

typedef on_newbb_proc<false> on_newbb_proc_f;
typedef on_newbb_proc<true> on_newbb_proc_t;

template <bool MT>
using on_newfn_proc = std::function<void(binary_base_t<MT> &, function_t &)>;

typedef on_newfn_proc<false> on_newfn_proc_f;
typedef on_newfn_proc<true> on_newfn_proc_t;

static inline void nop_on_block(basic_block_t,
                                basic_block_properties_t &) {}
static inline void nop_on_block_u(basic_block_index_t) {}

//
// performs accurate recursive traversal disassembly
//
class explorer_t {
  void *const jvptr = nullptr;
  disas_t &disas;
  tiny_code_generator_t &tcg;
  const unsigned VerbosityLevel;

  on_newbb_proc_f the_on_newbb_proc_f = [](binary_base_t<false> &, basic_block_t) {};
  on_newbb_proc_t the_on_newbb_proc_t = [](binary_base_t<true> &, basic_block_t) {};

  on_newfn_proc_f the_on_newfn_proc_f = [](binary_base_t<false> &, function_t &) {};
  on_newfn_proc_t the_on_newfn_proc_t = [](binary_base_t<true> &, function_t &) {};

  template <bool WithOnBlockProc, bool MT>
  bool split(binary_base_t<MT> &, llvm::object::Binary &,
             bbprop_t::exclusive_lock_guard<MT> e_lck_bb,
             bbmap_t::iterator it,
             const taddr_t Addr,
             basic_block_index_t,
             onblockproc_t obp = nop_on_block);

  template <bool WithOnBlockProc, bool MT>
  basic_block_index_t _explore_basic_block(
      binary_base_t<MT> &,
      llvm::object::Binary &,
      const taddr_t Addr,
      bool Speculative,
      const function_index_t ParentIdx = invalid_function_index,
      onblockproc_t obp = nop_on_block,
      onblockproc_u_t obp_u = nop_on_block_u);

  template <bool MT>
  function_index_t _explore_function(binary_base_t<MT> &,
                                     llvm::object::Binary &,
                                     const taddr_t Addr,
                                     const bool Speculative);

  template <bool MT>
  void _control_flow_to(binary_base_t<MT> &,
                        llvm::object::Binary &,
                        const taddr_t TermAddr,
                        const taddr_t Target,
                        const bool Speculative,
                        basic_block_t bb /* unused if !Speculative */);

  bool IsVerbose(void) const { return unlikely(VerbosityLevel >= 1); }
  bool IsVeryVerbose(void) const { return unlikely(VerbosityLevel >= 2); }

public:
  template <bool MT>
  explorer_t(jv_base_t<MT> &jv, disas_t &disas, tiny_code_generator_t &tcg,
             unsigned VerbosityLevel = 0)
      : jvptr(&jv), disas(disas), tcg(tcg), VerbosityLevel(VerbosityLevel) {}

  explorer_t(disas_t &disas, tiny_code_generator_t &tcg,
             unsigned VerbosityLevel = 0)
      : jvptr(nullptr), disas(disas), tcg(tcg), VerbosityLevel(VerbosityLevel) {}

  explorer_t(const explorer_t &other)
      : jvptr(nullptr), disas(other.disas), tcg(other.tcg),
        VerbosityLevel(other.VerbosityLevel),

        the_on_newbb_proc_f(other.the_on_newbb_proc_f),
        the_on_newbb_proc_t(other.the_on_newbb_proc_t),

        the_on_newfn_proc_f(other.the_on_newfn_proc_f),
        the_on_newfn_proc_t(other.the_on_newfn_proc_t) {}

  //
  // the objective is to translate all the code we can up until indirect
  // control-flow instructions. this is precisely what jove-bootstrap needs to
  // do when it sees new code before it can allow the tracee to continue
  // executing.
  //
  template <bool MT>
  basic_block_index_t explore_basic_block(binary_base_t<MT> &,
                                          llvm::object::Binary &,
                                          taddr_t Addr);

  template <bool MT>
  basic_block_index_t explore_basic_block(binary_base_t<MT> &,
                                          llvm::object::Binary &,
                                          taddr_t Addr,
                                          onblockproc_t obp,
                                          onblockproc_u_t obp_u);

  template <bool MT>
  function_index_t explore_function(binary_base_t<MT> &,
                                    llvm::object::Binary &,
                                    taddr_t Addr);

  template <bool MT = true>
  on_newbb_proc<MT> get_newbb_proc(void) const {
    if constexpr (MT)
      return the_on_newbb_proc_t;
    else
      return the_on_newbb_proc_f;
  }

  template <bool MT = true>
  void set_newbb_proc(on_newbb_proc<MT> proc) {
    if constexpr (MT)
      the_on_newbb_proc_t = proc;
    else
      the_on_newbb_proc_f = proc;
  }

  template <bool MT = true>
  on_newfn_proc<MT> get_newfn_proc(void) const {
    if constexpr (MT)
      return the_on_newfn_proc_t;
    else
      return the_on_newfn_proc_f;
  }

  // NOTE: the new function will initially posses an invalid basic block index
  // for Entry
  template <bool MT = true>
  void set_newfn_proc(on_newfn_proc<MT> proc) {
    if constexpr (MT)
      the_on_newfn_proc_t = proc;
    else
      the_on_newfn_proc_f = proc;
  }

  void *get_jvptr(void) const {
    return jvptr;
  }
};

}
