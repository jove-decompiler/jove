#include "jove/jove.h"

#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/seq.hpp>

namespace jove {

template <bool MT, bool MinSize>
bool function_analysis_t::AddCaller(const caller_t &caller) noexcept {
  using OurCallers_t = Callers_t<MT, MinSize>;

  if (void *const p = pCallers.load(MT ? boost::memory_order_acquire
                                       : boost::memory_order_relaxed)) {
    uintptr_t addr = reinterpret_cast<uintptr_t>(p);
    bool The_MT      = !!(addr & 1u);
    bool The_MinSize = !!(addr & 2u);
    addr &= ~3ULL;

    assert(The_MT == MT);
    assert(The_MinSize == MinSize);

    return reinterpret_cast<OurCallers_t *>(addr)->Insert(caller);
  }

  //
  // otherwise...
  //
  segment_manager_t &sm = get_segment_manager();

  static_assert(alignof(OurCallers_t) >= 4);
  unsigned align = alignof(OurCallers_t);
  if (!MinSize)
    align = std::max<unsigned>(align,
                               boost::unordered::detail::foa::cacheline_size);

  void *mem = sm.allocate_aligned(sizeof(OurCallers_t), align);
  assert(mem);
  OurCallers_t *const pTheCallers = new (mem) OurCallers_t(&sm);

  uintptr_t addr = reinterpret_cast<uintptr_t>(pTheCallers);
  assert(addr);
  addr |= (MT ? 1u : 0u) | (MinSize ? 2u : 0u);

  if constexpr (MT) {
    void *expected = nullptr;
    void *desired = reinterpret_cast<void *>(addr);
    if (pCallers.compare_exchange_strong(expected, desired,
                                         boost::memory_order_release,
                                         boost::memory_order_acquire)) {
      pTheCallers->Insert(caller);
      return true; /* it was empty before */
    }

    pTheCallers->~OurCallers_t();
    sm.deallocate(pTheCallers);

    uintptr_t expected_addr = reinterpret_cast<uintptr_t>(expected);
    bool The_MT      = !!(expected_addr & 1u);
    bool The_MinSize = !!(expected_addr & 2u);
    expected_addr &= ~3ULL;

    assert(The_MT == MT);
    assert(The_MinSize == MinSize);

    return reinterpret_cast<OurCallers_t *>(expected_addr)->Insert(caller);
  } else {
    pTheCallers ->Insert(caller);
    pCallers.store(reinterpret_cast<void *>(addr), boost::memory_order_relaxed);
    return true;
  }
}

function_analysis_t::~function_analysis_t() noexcept {
  if (void *const p = pCallers.load(AreWeMT ? boost::memory_order_acquire
                                            : boost::memory_order_relaxed)) {
    pCallers.store(nullptr, boost::memory_order_relaxed);

    uintptr_t addr = reinterpret_cast<uintptr_t>(p);
    bool MT      = !!(addr & 1u);
    bool MinSize = !!(addr & 2u);
    addr &= ~3ULL;

    segment_manager_t &sm = get_segment_manager();

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
    assert(addr);                                                              \
    reinterpret_cast<OurCallers_t *>(addr)->~OurCallers_t();                   \
    sm.deallocate(reinterpret_cast<OurCallers_t *>(addr));                     \
    addr = 0;                                                                  \
  }

    BOOST_PP_SEQ_FOR_EACH_PRODUCT(CALLERS_CASE,
                                  (MT_POSSIBILTIES)(MINSIZE_POSSIBILTIES))
  }
}

template <bool MT, bool MinSize>
ip_call_graph_base_t<MT>::vertex_descriptor
function_analysis_t::ReverseCGVert(jv_base_t<MT, MinSize> &jv) {
  auto &RCG = jv.Analysis.ReverseCallGraph;

  call_graph_index_t Res =
      this->ReverseCGVertIdxHolder.Idx.load(boost::memory_order_relaxed);

  if (unlikely(!is_call_graph_index_valid(Res))) {
    auto e_lck = this->ReverseCGVertIdxHolder.exclusive_access<MT>();

    Res = this->ReverseCGVertIdxHolder.Idx.load(boost::memory_order_relaxed);
    if (likely(!is_call_graph_index_valid(Res))) {
      Res = RCG.index_of_add_vertex(&jv.get_segment_manager());
      this->ReverseCGVertIdxHolder.Idx.store(Res, boost::memory_order_relaxed);

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
  template ip_call_graph_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))>::vertex_descriptor \
  function_analysis_t::ReverseCGVert(                                          \
      jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),                      \
                GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &);                  \
  template bool                                                                \
  function_analysis_t::AddCaller<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),     \
                                 GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))>(    \
      const caller_t &);
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
