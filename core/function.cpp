#include "jove/jove.h"

#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/seq.hpp>

namespace jove {

template <bool MT>
function_t::function_t(binary_base_t<MT> &b, function_index_t Idx) noexcept
    : BIdx(b.Idx /* could be invalid */), Idx(Idx),
      Callers(b.get_segment_manager()) {}

function_t::function_t(segment_manager_t *sm) noexcept
    : Callers(sm) {}

template <bool MT>
ip_call_graph_base_t<MT>::vertex_descriptor
function_t::ReverseCGVert(jv_base_t<MT> &jv) {
  auto &RCG = jv.Analysis.ReverseCallGraph;

  call_graph_index_t Res =
      this->ReverseCGVertIdxHolder.V.load(std::memory_order_relaxed);

  if (unlikely(!is_call_graph_index_valid(Res))) {
    auto e_lck = this->ReverseCGVertIdxHolder.exclusive_access<MT>();

    Res = this->ReverseCGVertIdxHolder.V.load(std::memory_order_relaxed);
    if (likely(!is_call_graph_index_valid(Res))) {
      Res = RCG.index_of_add_vertex(jv.get_segment_manager());
      this->ReverseCGVertIdxHolder.V.store(Res, std::memory_order_relaxed);

      dynamic_target_t X = target_of_function(*this);
      assert(is_dynamic_target_valid(X));

      call_graph_node_properties_t::pair X_{X.first, X.second};
      RCG[RCG.template vertex<MT>(Res)].X.store(X_, std::memory_order_relaxed);
    }
  }

  assert(is_call_graph_index_valid(Res));

  return RCG.template vertex<MT>(Res);
}

#define VALUES_TO_INSTANTIATE_WITH                                             \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template function_t::function_t(binary_base_t<GET_VALUE(elem)> &,            \
                                  function_index_t Idx);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template ip_call_graph_base_t<GET_VALUE(elem)>::vertex_descriptor            \
  function_t::ReverseCGVert(jv_base_t<GET_VALUE(elem)> &);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

}
