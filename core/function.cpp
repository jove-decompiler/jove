#include "jove/jove.h"

#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/seq.hpp>

namespace jove {

template <bool MT, bool MinSize>
function_t::function_t(binary_base_t<MT, MinSize> &b, function_index_t Idx) noexcept
    : BIdx(b.Idx /* could be invalid */), Idx(Idx), sm_(b.get_segment_manager()) {}

function_t::function_t(segment_manager_t *sm) noexcept : sm_(sm) {}

template <bool MT, bool MinSize>
bool function_t::AddCaller(jv_file_t &jv_file,
                           const caller_t &caller) noexcept {
  using OurCallers_t = Callers_t<MT, MinSize>;

  if (void *const p = pCallers.Load(std::memory_order_relaxed)) {
    uintptr_t p_addr = reinterpret_cast<uintptr_t>(p);
    bool The_MT      = !!(p_addr & 1u);
    bool The_MinSize = !!(p_addr & 2u);
    p_addr &= ~3ULL;

    assert(The_MT == MT);
    assert(The_MinSize == MinSize);

    return reinterpret_cast<OurCallers_t *>(p_addr)->Insert(caller);
  }

  //
  // otherwise...
  //
  ip_unique_ptr<OurCallers_t> TheCallers(
      boost::interprocess::make_managed_unique_ptr(
          jv_file.construct<OurCallers_t>(
              boost::interprocess::anonymous_instance)(
              jv_file.get_segment_manager()),
          jv_file));

  OurCallers_t &Callers = *TheCallers.get().get();
  uintptr_t Callers_addr = reinterpret_cast<uintptr_t>(&Callers);
  assert(Callers_addr);
  Callers_addr |= (MT ? 1u : 0u) | (MinSize ? 2u : 0u);

  void *expected = nullptr;
  void *desired = reinterpret_cast<void *>(Callers_addr);
  if (pCallers.CompareExchangeStrong(expected, desired,
                                     std::memory_order_relaxed,
                                     std::memory_order_relaxed)) {
    Callers.Insert(caller);
    TheCallers.release();

    sm_ = jv_file.get_segment_manager();
    return true; /* it was empty before */
  }

  uintptr_t expected_addr = reinterpret_cast<uintptr_t>(expected);
  expected_addr &= ~3ULL;

  return reinterpret_cast<OurCallers_t *>(expected_addr)->Insert(caller);
}

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

#define CALLERS_CASE(r, product)                                               \
  if (MT      == GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)) &&                   \
      MinSize == GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))) {                   \
    using OurCallers_t = Callers_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),   \
                                   GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>;  \
    assert(p_addr);                                                            \
    assert(sm_);                                                               \
    sm_->destroy_ptr(reinterpret_cast<OurCallers_t *>(p_addr));                \
    p_addr = 0;                                                                \
  }

    BOOST_PP_SEQ_FOR_EACH_PRODUCT(CALLERS_CASE,
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
                GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &);                  \
  template bool                                                                \
  function_t::AddCaller<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),              \
                        GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>(             \
      jv_file_t &, const caller_t &);
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
