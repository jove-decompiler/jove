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
  template <bool MT, bool MinSize>
  invalid_control_flow_exception(binary_base_t<MT, MinSize> &b, uint64_t pc)
      : name_of_binary(b.Name.c_str()), pc(pc) {}
};

struct tiny_code_generator_t;

template <bool MT>
using onblockproc_t = std::function<void(
    typename ip_icfg_base_t<MT>::vertex_descriptor, bbprop_t &)>;

using onblockproc_u_t = std::function<void(basic_block_index_t)>;

template <bool MT, bool MinSize>
using on_newbb_proc_t = std::function<void(
    binary_base_t<MT, MinSize> &,
    typename ip_icfg_base_t<MT>::vertex_descriptor)>;

template <bool MT, bool MinSize>
using on_newfn_proc_t =
    std::function<void(binary_base_t<MT, MinSize> &, function_t &)>;

template <bool MT>
static inline void nop_on_block(typename ip_icfg_base_t<MT>::vertex_descriptor,
                                bbprop_t &) {}
static inline void nop_on_block_u(basic_block_index_t) {}

template <bool MT, bool MinSize>
static inline void
nop_on_newbb_proc(binary_base_t<MT, MinSize> &,
                  typename ip_icfg_base_t<MT>::vertex_descriptor) {}

template <bool MT, bool MinSize>
static inline void nop_on_newfn_proc(binary_base_t<MT, MinSize> &,
                                     function_t &) {}

//
// performs accurate recursive traversal disassembly
//
template <bool MT, bool MinSize>
class explorer_t : public VerboseThing {
  using jv_t = jv_base_t<MT, MinSize>;
  using binary_t = binary_base_t<MT, MinSize>;
  using bb_t = ip_icfg_base_t<MT>::vertex_descriptor;

  //
  // friends
  //
#define VALUES1 ((true))((false))
#define VALUES2 ((true))((false))
#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)
#define DO_FRIEND(r, product)                                                  \
  friend explorer_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),                  \
                    GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))>;
  BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_FRIEND, (VALUES1)(VALUES2))
#undef DO_FRIEND
#undef GET_VALUE
#undef VALUES1
#undef VALUES2

  jv_file_t &jv_file;
  boost::optional<jv_t &> maybe_jv;
  disas_t &disas;
  tiny_code_generator_t &tcg;

  on_newbb_proc_t<MT, MinSize> on_newbb_proc = nop_on_newbb_proc<MT, MinSize>;
  on_newfn_proc_t<MT, MinSize> on_newfn_proc = nop_on_newfn_proc<MT, MinSize>;

  template <bool WithOnBlockProc>
  bool split(binary_t &,
             llvm::object::Binary &,
             bbprop_t::exclusive_lock_guard<MT> e_lck_bb,
             bbmap_t::iterator it,
             const taddr_t Addr,
             basic_block_index_t,
             onblockproc_t<MT> obp = nop_on_block<MT>);

  template <bool WithOnBlockProc>
  basic_block_index_t _explore_basic_block(
      binary_t &,
      llvm::object::Binary &,
      const taddr_t Addr,
      bool Speculative,
      const function_index_t ParentIdx = invalid_function_index,
      onblockproc_t<MT> obp = nop_on_block<MT>,
      onblockproc_u_t obp_u = nop_on_block_u);

  function_index_t _explore_function(binary_t &,
                                     llvm::object::Binary &,
                                     const taddr_t Addr,
                                     const bool Speculative);

  void _control_flow_to(binary_t &,
                        llvm::object::Binary &,
                        const taddr_t TermAddr,
                        const taddr_t Target,
                        const bool Speculative,
                        bb_t bb /* unused if !Speculative */);

public:
  explicit explorer_t(jv_file_t &jv_file, jv_t &jv, disas_t &disas,
                      tiny_code_generator_t &tcg,
                      unsigned VerbosityLevel = 0) noexcept
      : VerboseThing(VerbosityLevel), jv_file(jv_file), maybe_jv(jv),
        disas(disas), tcg(tcg) {}

  explicit explorer_t(jv_file_t &jv_file, disas_t &disas,
                      tiny_code_generator_t &tcg,
                      unsigned VerbosityLevel = 0) noexcept
      : VerboseThing(VerbosityLevel), jv_file(jv_file), maybe_jv(boost::none),
        disas(disas), tcg(tcg) {}

  template <bool MT2>
  explicit explorer_t(const explorer_t<MT2, MinSize> &other) noexcept
      : VerboseThing(VerbosityLevel),
        jv_file(other.jv_file),
        maybe_jv(boost::none),
        disas(other.disas),
        tcg(other.tcg) {
    if constexpr (MT == MT2) {
      on_newbb_proc = other.on_newbb_proc;
      on_newfn_proc = other.on_newfn_proc;
    }
  }

  //
  // the objective is to translate all the code we can up until indirect
  // control-flow instructions. this is precisely what jove-bootstrap needs to
  // do when it sees new code before it can allow the tracee to continue
  // executing.
  //
  basic_block_index_t explore_basic_block(binary_t &,
                                          llvm::object::Binary &,
                                          taddr_t Addr);

  basic_block_index_t explore_basic_block(binary_t &,
                                          llvm::object::Binary &,
                                          taddr_t Addr,
                                          onblockproc_t<MT> obp,
                                          onblockproc_u_t obp_u);

  function_index_t explore_function(binary_t &,
                                    llvm::object::Binary &,
                                    taddr_t Addr);

  on_newbb_proc_t<MT, MinSize> get_newbb_proc(void) const {
    return on_newbb_proc;
  }
  void set_newbb_proc(on_newbb_proc_t<MT, MinSize> proc) {
    on_newbb_proc = proc;
  }

  // NOTE: the new function will initially posses an invalid basic block index
  // for Entry
  on_newfn_proc_t<MT, MinSize> get_newfn_proc(void) const {
    return on_newfn_proc;
  }
  void set_newfn_proc(on_newfn_proc_t<MT, MinSize> proc) {
    on_newfn_proc = proc;
  }

  boost::optional<jv_t &> get_jv(void) const {
    return maybe_jv;
  }

  void set_jv(boost::optional<jv_t &> x) {
    maybe_jv.swap(x);
  }
};

}
