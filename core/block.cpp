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

  auto *const dst = out.data();
  const auto *const src = old.data();

  if (idx > 0)
    std::memcpy(dst, src, idx * sizeof(function_index_t));
  dst[idx] = FIdx;
  const auto n = old.size();
  if (idx < n)
    std::memcpy(dst + idx + 1, src + idx, (n - idx) * sizeof(function_index_t));

  return true;
}

template <bool MT>
void basic_block_properties_t::Parents_t::insert(function_index_t FIdx,
                                                 binary_base_t<MT> &b) {
  const ip_func_index_vec &FIdxVec = get<MT>();
  if constexpr (MT) {
    {
      ip_func_index_vec copy(FIdxVec.get_allocator().get_segment_manager());
      if (!copy_and_insert_sort(FIdxVec, copy, FIdx))
        return;

      const ip_func_index_vec *TheVecPtr = nullptr;

      auto grab = [&](const ip_func_index_vec &TheSet) -> void {
        TheVecPtr = &TheSet;
      };

      b.FIdxVecs.insert_and_cvisit(boost::move(copy), grab, grab);

      assert(TheVecPtr);
      set<MT>(*TheVecPtr);
    }

    __attribute__((musttail)) return insert<MT>(FIdx, b);
  } else {
    ip_func_index_vec copy(FIdxVec.get_allocator().get_segment_manager());
    if (copy_and_insert_sort(FIdxVec, copy, FIdx))
      set<MT>(*b.FIdxVecs.insert(boost::move(copy)).first);
  }
}

bool basic_block_properties_t::doInsertDynTarget(const dynamic_target_t &X,
                                                 jv_file_t &jv_file) {
  if (auto *p = DynTargets._p.Load(std::memory_order_relaxed))
    return p->insert(X);

  ip_unique_ptr<ip_dynamic_target_set<>> TheDynTargets(
      boost::interprocess::make_managed_unique_ptr(
          jv_file.construct<ip_dynamic_target_set<>>(
              boost::interprocess::anonymous_instance)(
              jv_file.get_segment_manager()),
          jv_file));

  ip_dynamic_target_set<> *expected = nullptr;
  ip_dynamic_target_set<> *desired = TheDynTargets.get().get();
  if (DynTargets._p.CompareExchangeStrong(
          expected,
          desired,
          std::memory_order_relaxed, std::memory_order_relaxed)) {
    DynTargets._sm = jv_file.get_segment_manager();
    TheDynTargets.release();
    desired->insert(X);
    return true; /* it was empty before */
  }

  return expected->insert(X);
}

template <bool MT>
bool basic_block_properties_t::insertDynTarget(binary_index_t ThisBIdx,
                                               const dynamic_target_t &X,
                                               jv_file_t &jv_file,
                                               jv_base_t<MT> &jv) {
  assert(is_binary_index_valid(ThisBIdx));
  auto &caller_b = jv.Binaries.at(ThisBIdx);

  function_t &callee = function_of_target(X, jv);
  callee.InvalidateAnalysis();
  callee.Callers.insert<MT>(ThisBIdx, Term.Addr);

  bool res = doInsertDynTarget(X, jv_file);

  if (res) {
    auto &RCG = jv.Analysis.ReverseCallGraph;
    const auto &ParentsVec = Parents.get<MT>();

    std::for_each(std::execution::par_unseq,
                  ParentsVec.cbegin(),
                  ParentsVec.cend(), [&](function_index_t FIdx) {
                    function_t &caller = caller_b.Analysis.Functions.at(FIdx);
                    caller.InvalidateAnalysis();

                    RCG.template add_edge<MT>(callee.ReverseCGVert<MT>(jv),
                                              caller.ReverseCGVert<MT>(jv));
                  });
  }

  return res;
}

template <bool MT>
void basic_block_properties_t::InvalidateAnalysis(jv_base_t<MT> &jv,
                                                  binary_base_t<MT> &b) {
  this->Analysis.Stale = true;

  struct function_invalidator_t : public boost::default_dfs_visitor {
    jv_base_t<MT> &jv;

    function_invalidator_t(jv_base_t<MT> &jv) : jv(jv) {}

    void discover_vertex(ip_call_graph_base_t<MT>::vertex_descriptor V,
                         const ip_call_graph_base_t<MT>::type &RCG) const {
      dynamic_target_t X = RCG[V].X;

      assert(is_dynamic_target_valid(X));

      function_of_target(X, jv).InvalidateAnalysis();
    }
  };

  function_invalidator_t invalidator(jv);

  const auto &ParentsVec = Parents.get<MT>();
  std::for_each(std::execution::par_unseq,
                ParentsVec.cbegin(),
                ParentsVec.cend(), [&](function_index_t FIdx) {
                  function_t &f = b.Analysis.Functions.at(FIdx);

                  auto V = f.ReverseCGVert<MT>(jv);

                  jv.Analysis.ReverseCallGraph.depth_first_visit(V, invalidator);
                });
}

#define VALUES_TO_INSTANTIATE_WITH                                             \
    ((true))                                                                   \
    ((false))
#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template bool basic_block_properties_t::insertDynTarget(                     \
      binary_index_t ThisBIdx, const dynamic_target_t &, jv_file_t &,          \
      jv_base_t<GET_VALUE(elem)> &);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template void basic_block_properties_t::Parents_t::insert(                   \
      function_index_t, binary_base_t<GET_VALUE(elem)> &);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template void basic_block_properties_t::InvalidateAnalysis<GET_VALUE(elem)>( \
      jv_base_t<GET_VALUE(elem)> &, binary_base_t<GET_VALUE(elem)> &);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

}
