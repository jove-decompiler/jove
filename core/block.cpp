#include "jove/jove.h"

#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/seq.hpp>

namespace jove {

static bool copy_and_insert_sort(const ip_func_index_vec &old,
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

template <bool MT, bool MinSize>
void bbprop_t::Parents_t::insert(function_index_t FIdx,
                                 binary_base_t<MT, MinSize> &b) {
  {
    const ip_func_index_vec &FIdxVec = get<MT>();

    ip_func_index_vec copy(b.get_segment_manager());
    if (!copy_and_insert_sort(FIdxVec, copy, FIdx))
      return;

    set<MT>(b.FIdxVecs.Add(boost::move(copy)));
  }

  if constexpr (MT)
    __attribute__((musttail)) return insert(FIdx, b);
}

template <bool MT, bool MinSize>
bool bbprop_t::doInsertDynTarget(const dynamic_target_t &X,
                                 jv_file_t &jv_file,
                                 jv_base_t<MT, MinSize> &) {
  using OurDynTargets_t = DynTargets_t<MT, MinSize>;

  if (auto *p = pDynTargets.Load(std::memory_order_relaxed))
    return static_cast<OurDynTargets_t *>(p)->Insert(X);

  //
  // otherwise...
  //
  ip_unique_ptr<OurDynTargets_t> TheDynTargets(
      boost::interprocess::make_managed_unique_ptr(
          jv_file.construct<OurDynTargets_t>(
              boost::interprocess::anonymous_instance)(
              jv_file.get_segment_manager()),
          jv_file));

  OurDynTargets_t &DynTargets = *TheDynTargets.get().get();

  void *expected = nullptr;
  void *desired = &DynTargets;
  if (pDynTargets.CompareExchangeStrong(
          expected,
          desired,
          std::memory_order_relaxed, std::memory_order_relaxed)) {
    DynTargets.Insert(X);
    TheDynTargets.release();

    sm_ = jv_file.get_segment_manager();
    return true; /* it was empty before */
  }

  return static_cast<OurDynTargets_t *>(expected)->Insert(X);
}

template <bool MT, bool MinSize>
bool bbprop_t::insertDynTarget(binary_index_t ThisBIdx,
                               const dynamic_target_t &X,
                               jv_file_t &jv_file,
                               jv_base_t<MT, MinSize> &jv) {
  assert(is_binary_index_valid(ThisBIdx));
  auto &caller_b = jv.Binaries.at(ThisBIdx);

  function_t &callee = function_of_target(X, jv);
  callee.InvalidateAnalysis();
  callee.Callers(jv).Insert(caller_t(ThisBIdx, Term.Addr));

  bool res = doInsertDynTarget(X, jv_file, jv);

  if (res) {
    auto &RCG = jv.Analysis.ReverseCallGraph;
    const auto &ParentsVec = Parents.template get<MT>();

    std::for_each(maybe_par_unseq,
                  ParentsVec.cbegin(),
                  ParentsVec.cend(), [&](function_index_t FIdx) {
                    function_t &caller = caller_b.Analysis.Functions.at(FIdx);
                    caller.InvalidateAnalysis();

                    RCG.template add_edge<MT>(
                        callee.ReverseCGVert(jv),
                        caller.ReverseCGVert(jv));
                  });
  }

  return res;
}

template <bool MT, bool MinSize>
void bbprop_t::InvalidateAnalysis(jv_base_t<MT, MinSize> &jv,
                                  binary_base_t<MT, MinSize> &b) {
  this->Analysis.Stale = true;

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

                  auto V = f.ReverseCGVert(jv);

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
      binary_index_t ThisBIdx, const dynamic_target_t &, jv_file_t &,          \
      jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),                      \
                GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &);                  \
  template void bbprop_t::InvalidateAnalysis(                                  \
      jv_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),                      \
                GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &,                   \
      binary_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(0, product)),                  \
                    GET_VALUE(BOOST_PP_SEQ_ELEM(1, product))> &);

BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
