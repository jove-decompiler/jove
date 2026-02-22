#include "jove/jove.h"

#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/seq.hpp>

namespace jove {

static bool copy_and_insert_sorted(const ip_func_index_vec &old,
                                   ip_func_index_vec &out,
                                   function_index_t FIdx) {
  auto it = std::lower_bound(old.cbegin(), old.cend(), FIdx);

  //
  // if already present, bail out
  //
  if (it != old.cend() && *it == FIdx)
    return false;

  //
  // find the place to insert (first element >= FIdx)
  //
  const auto idx = static_cast<size_t>(it - old.cbegin());

  out.resize(old.size() + 1);

  function_index_t *const dst = out.data();
  const function_index_t *const src = old.data();

  if (idx > 0)
    std::memcpy(dst, src, idx * sizeof(function_index_t));
  dst[idx] = FIdx;
  const auto n = old.size();
  if (idx < n)
    std::memcpy(dst + idx + 1, src + idx, (n - idx) * sizeof(function_index_t));

  return true;
}

bbprop_t::~bbprop_t() noexcept {
  if (void *const p = pDynTargets.load(AreWeMT ? boost::memory_order_acquire
                                               : boost::memory_order_relaxed)) {
    pDynTargets.store(nullptr, boost::memory_order_relaxed);

    uintptr_t addr = reinterpret_cast<uintptr_t>(p);

    const unsigned tag = addr & 0x3u;
    const bool MT      = !!(addr & 1u);
    const bool MinSize = !!(addr & 2u);

    addr &= ~3ULL;

    segment_manager_t &sm = get_segment_manager();

#define MT_POSSIBILTIES  \
    (0)                  \
    (1)
#define MINSIZE_POSSIBILTIES \
    (0)                      \
    (1)

#define DYNTARGETS_ENTRY(r, product) \
  [(BOOST_PP_SEQ_ELEM(0, product) |  \
   (BOOST_PP_SEQ_ELEM(1, product) << 1))] = &&BOOST_PP_CAT(do_,BOOST_PP_CAT(BOOST_PP_SEQ_ELEM(0, product),BOOST_PP_SEQ_ELEM(1, product))) ,

    static const void *const table[4] = {
BOOST_PP_SEQ_FOR_EACH_PRODUCT(DYNTARGETS_ENTRY, (MT_POSSIBILTIES)(MINSIZE_POSSIBILTIES))
    };

    goto *table[tag];

#define DYNTARGETS_CASE(r, product)                                                           \
  BOOST_PP_CAT(do_,BOOST_PP_CAT(BOOST_PP_SEQ_ELEM(0, product),BOOST_PP_SEQ_ELEM(1, product))) : {\
    using TheDynTargets_t =                                        \
        DynTargets_t<BOOST_PP_SEQ_ELEM(0, product),                \
                     BOOST_PP_SEQ_ELEM(1, product)>;               \
    reinterpret_cast<TheDynTargets_t *>(addr)->~TheDynTargets_t(); \
    sm.deallocate(reinterpret_cast<TheDynTargets_t *>(addr));      \
    goto out;                                                      \
  }

BOOST_PP_SEQ_FOR_EACH_PRODUCT(DYNTARGETS_CASE, (MT_POSSIBILTIES)(MINSIZE_POSSIBILTIES))

out:
  }
}

template <bool MT, bool MinSize>
void bbprop_t::Parents_t::insert(function_index_t FIdx,
                                 binary_base_t<MT, MinSize> &b) {
  {
    const ip_func_index_vec &FIdxVec = get<MT>();

    ip_func_index_vec copy(&b.get_segment_manager());
    if (!copy_and_insert_sorted(FIdxVec, copy, FIdx))
      return;

    set<MT>(b.FIdxVecs.Add(boost::move(copy)));
  }

  if constexpr (MT)
    __attribute__((musttail)) return insert(FIdx, b);
}

template <bool MT, bool MinSize>
bool bbprop_t::doInsertDynTarget(const dynamic_target_t &X) {
  using OurDynTargets_t = DynTargets_t<MT, MinSize>;

  if (void *const p = pDynTargets.load(MT ? boost::memory_order_acquire
                                          : boost::memory_order_relaxed)) {
    uintptr_t p_addr = reinterpret_cast<uintptr_t>(p);
    bool The_MT      = !!(p_addr & 1u);
    bool The_MinSize = !!(p_addr & 2u);
    p_addr &= ~3ULL;

    assert(The_MT == MT);
    assert(The_MinSize == MinSize);

    return reinterpret_cast<OurDynTargets_t *>(p_addr)->Insert(X);
  }

  //
  // otherwise...
  //
  segment_manager_t &sm = get_segment_manager();

  static_assert(alignof(OurDynTargets_t) >= 4);
  unsigned align = alignof(OurDynTargets_t);
  if (!MinSize)
    align = std::max<unsigned>(align,
                               boost::unordered::detail::foa::cacheline_size);

  void *mem = sm.allocate_aligned(sizeof(OurDynTargets_t), align);
  assert(mem);

  OurDynTargets_t *const pTheDynTargets = new (mem) OurDynTargets_t(&sm);

  uintptr_t addr = reinterpret_cast<uintptr_t>(pTheDynTargets);
  assert(addr);
  addr |= (MT ? 1u : 0u) | (MinSize ? 2u : 0u);

  if constexpr (MT) {
    void *expected = nullptr;
    void *desired = reinterpret_cast<void *>(addr);
    if (pDynTargets.compare_exchange_strong(expected, desired,
                                            boost::memory_order_release,
                                            boost::memory_order_acquire)) {
      pTheDynTargets->Insert(X);
      return true; /* it was empty before */
    }

    pTheDynTargets->~OurDynTargets_t();
    sm.deallocate(pTheDynTargets);

    uintptr_t expected_addr = reinterpret_cast<uintptr_t>(expected);
    bool The_MT      = !!(expected_addr & 1u);
    bool The_MinSize = !!(expected_addr & 2u);
    expected_addr &= ~3ULL;

    assert(The_MT == MT);
    assert(The_MinSize == MinSize);

    return reinterpret_cast<OurDynTargets_t *>(expected_addr)->Insert(X);
  } else {
    pTheDynTargets->Insert(X);
    pDynTargets.store(reinterpret_cast<void *>(addr), boost::memory_order_relaxed);
    return true;
  }
}

template <bool MT, bool MinSize>
bool bbprop_t::insertDynTarget(binary_index_t ThisBIdx,
                               const dynamic_target_t &X,
                               jv_base_t<MT, MinSize> &jv) {
  assert(is_binary_index_valid(ThisBIdx));
  auto &caller_b = jv.Binaries.at(ThisBIdx);

  function_t &callee = function_of_target(X, jv);

  bool res = doInsertDynTarget<MT, MinSize>(X);
  if (res) {
    callee.InvalidateAnalysis();
    callee.Analysis.AddCaller<MT, MinSize>(caller_t(ThisBIdx, Term.Addr));

    auto &RCG = jv.Analysis.ReverseCallGraph;
    const auto &ParentsVec = Parents.template get<MT>();

    auto s_lck = RCG.shared_access();

    std::for_each(maybe_par_unseq,
                  ParentsVec.cbegin(),
                  ParentsVec.cend(), [&](function_index_t FIdx) {
                    function_t &caller = caller_b.Analysis.Functions.at(FIdx);
                    caller.InvalidateAnalysis();

                    RCG.template add_edge<MT>(
                        callee.Analysis.ReverseCGVert(jv),
                        caller.Analysis.ReverseCGVert(jv));
                  });
  }

  return res;
}

template <bool MT, bool MinSize>
void bbprop_t::InvalidateAnalysis(jv_base_t<MT, MinSize> &jv,
                                  binary_base_t<MT, MinSize> &b) {
  this->Analysis.Stale.test_and_set(boost::memory_order_relaxed);

  struct function_invalidator_t : public boost::default_dfs_visitor {
    jv_base_t<MT, MinSize> &jv;

    function_invalidator_t(jv_base_t<MT, MinSize> &jv) : jv(jv) {}

    void discover_vertex(ip_call_graph_base_t<MT>::vertex_descriptor V,
                         const ip_call_graph_base_t<MT>::type &RCG) const {
      dynamic_target_t X = RCG[V].X;

      assert(is_dynamic_target_valid(X));

      function_of_target(X, jv).InvalidateAnalysis();
    }
  };

  function_invalidator_t invalidator(jv);

  const auto &ParentsVec = Parents.template get<MT>();
  std::for_each(maybe_par_unseq,
                ParentsVec.cbegin(),
                ParentsVec.cend(), [&](function_index_t FIdx) {
                  function_t &f = b.Analysis.Functions.at(FIdx);

                  f.Analysis.Invalidate();

                  auto V = f.Analysis.ReverseCGVert(jv);

                  jv.Analysis.ReverseCallGraph.depth_first_visit(V, invalidator);
                });
}

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template void bbprop_t::Parents_t::insert(                                   \
      function_index_t,                                                        \
      binary_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),                  \
                    GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &);              \
  template bool bbprop_t::insertDynTarget(                                     \
      binary_index_t ThisBIdx, const dynamic_target_t &,                       \
      jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),                      \
                GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &);                  \
  template void bbprop_t::InvalidateAnalysis(                                  \
      jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),                      \
                GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &,                   \
      binary_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),                  \
                    GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &);

BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
