#include "jove/jove.h"

#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/seq.hpp>

namespace jove {

template <bool MT, bool MinSize>
function_t::function_t(binary_base_t<MT, MinSize> &b, function_index_t Idx) noexcept
    : BIdx(b.Idx /* could be invalid */), Idx(Idx), sm_(b.get_segment_manager()) {}

function_t::function_t(segment_manager_t *sm) noexcept : sm_(sm) {}

function_t::~function_t() noexcept {
  if (void *const p = pCallers.Load(std::memory_order_relaxed)) {
    pCallers.Store(nullptr, std::memory_order_relaxed);

    uintptr_t p_addr = reinterpret_cast<uintptr_t>(p);
    bool MT      = !!(p_addr & 1u);
    bool MinSize = !!(p_addr & 2u);
    p_addr &= ~3ULL;

#define MT_POSSIBILTIES                                                        \
    ((true))                                                                   \
    ((false))
#define MINSIZE_POSSIBILTIES                                                   \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_DYNTARGETS_CASE(r, product)                                         \
  if (MT      == GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)) &&      \
      MinSize == GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))) {      \
    using OurCallers_t =                                                    \
        Callers_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),           \
                  GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>;          \
    assert(p_addr); \
    assert(sm_);\
    sm_->destroy_ptr(reinterpret_cast<OurCallers_t *>(p_addr));\
    p_addr = 0; \
  }

  BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_DYNTARGETS_CASE,
                                (MT_POSSIBILTIES)(MINSIZE_POSSIBILTIES))
  }
}

template <bool MT, bool MinSize>
ip_call_graph_base_t<MT>::vertex_descriptor
function_t::ReverseCGVert(jv_base_t<MT, MinSize> &jv) {
  auto &RCG = jv.Analysis.ReverseCallGraph;

  call_graph_index_t Res =
      this->ReverseCGVertIdxHolder.Idx.load(std::memory_order_relaxed);

  if (unlikely(!is_call_graph_index_valid(Res))) {
    auto e_lck = this->ReverseCGVertIdxHolder.exclusive_access<MT>();

    Res = this->ReverseCGVertIdxHolder.Idx.load(std::memory_order_relaxed);
    if (likely(!is_call_graph_index_valid(Res))) {
      Res = RCG.index_of_add_vertex(jv.get_segment_manager());
      this->ReverseCGVertIdxHolder.Idx.store(Res, std::memory_order_relaxed);

      dynamic_target_t X = target_of_function(*this);
      assert(is_dynamic_target_valid(X));

      RCG[RCG.template vertex<MT>(Res)].X = X;
    }
  }

  assert(is_call_graph_index_valid(Res));

  return RCG.template vertex<MT>(Res);
}

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))
#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template function_t::function_t(                                             \
      binary_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),                  \
                    GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &,               \
      function_index_t Idx);                                                   \
  template ip_call_graph_base_t<GET_VALUE(                                     \
      BOOST_PP_SEQ_ELEM(0, product))>::vertex_descriptor                       \
  function_t::ReverseCGVert(                                                   \
      jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),                      \
                GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &);
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
