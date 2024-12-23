#include "jove/jove.h"

#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/elem.hpp>
#include <boost/preprocessor/seq/seq.hpp>

namespace jove {

template <bool MT>
bool basic_block_properties_t::IsParent(function_index_t FIdx) const {
  ip_sharable_lock<ip_sharable_mutex> s_lck(Parents._mtx);

  if (!Parents._p)
    return false;

  return Parents._p->contains(FIdx);
}

template <bool MT>
bool basic_block_properties_t::HasParent(void) const {
  ip_sharable_lock<ip_sharable_mutex> s_lck(Parents._mtx);

  if (!Parents._p)
    return false;

  return !Parents._p->empty();
}

template <bool MT>
void basic_block_properties_t::AddParent(function_index_t FIdx, jv_base_t<MT> &jv) {
  ip_func_index_set Idxs(jv.get_segment_manager());

  {
    ip_sharable_lock<ip_sharable_mutex> s_lck_parents(Parents._mtx);

    if (Parents._p) {
      if (Parents._p->contains(FIdx))
        return;

      Idxs = *Parents._p;
    }
  }

  {
    bool success = Idxs.insert(FIdx).second;
    assert(success);
  }

  {
    ip_sharable_lock<ip_sharable_mutex> s_lck_sets(jv.FIdxSetsMtx);

    auto it = jv.FIdxSets.find(Idxs);
    if (it != jv.FIdxSets.end()) {
      ip_scoped_lock<ip_sharable_mutex> e_lck_parents(Parents._mtx);

      Parents._p = &(*it);
      return;
    }
  }

  ip_scoped_lock<ip_sharable_mutex> e_lck_sets(jv.FIdxSetsMtx);
  ip_scoped_lock<ip_sharable_mutex> e_lck_parents(Parents._mtx);

  Parents._p = &(*jv.FIdxSets.insert(boost::move(Idxs)).first);
}

template <bool MT>
void basic_block_properties_t::GetParents(func_index_set &out) const {
  ip_sharable_lock<ip_sharable_mutex> s_lck(Parents._mtx);

  if (!Parents._p)
    return;

  const ip_func_index_set &parents = *Parents._p;
  out.insert(parents.begin(), parents.end());
}

bool basic_block_properties_t::doInsertDynTarget(const dynamic_target_t &X,
                                                 jv_file_t &jv_file) {
  if (auto *p = DynTargets._p.Load(std::memory_order_relaxed))
    return p->insert(X);

  ip_unique_ptr<ip_dynamic_target_set> TheDynTargets(
      boost::interprocess::make_managed_unique_ptr(
          jv_file.construct<ip_dynamic_target_set>(
              boost::interprocess::anonymous_instance)(
              jv_file.get_segment_manager()),
          jv_file));

  ip_dynamic_target_set *expected = nullptr;
  ip_dynamic_target_set *desired = TheDynTargets.get().get();
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
  function_of_target(X, jv).Callers.emplace(ThisBIdx, Term.Addr);
  return doInsertDynTarget(X, jv_file);
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
  template bool basic_block_properties_t::IsParent<GET_VALUE(elem)>(           \
      function_index_t FIdx) const;
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template void basic_block_properties_t::GetParents<GET_VALUE(elem)>(         \
      func_index_set &) const;
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template void basic_block_properties_t::AddParent<GET_VALUE(elem)>(          \
      function_index_t, jv_base_t<GET_VALUE(elem)> &);
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

#define DO_INSTANTIATE(r, data, elem)                                          \
  template bool basic_block_properties_t::HasParent<GET_VALUE(elem)>(void) const;
BOOST_PP_SEQ_FOR_EACH(DO_INSTANTIATE, void, VALUES_TO_INSTANTIATE_WITH)

}
