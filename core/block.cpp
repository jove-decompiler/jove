#include "jove/jove.h"

namespace jove {

bool basic_block_properties_t::IsParent(function_index_t FIdx) const {
  ip_sharable_lock<ip_sharable_mutex> s_lck(Parents._mtx);

  if (!Parents._p)
    return false;

  return Parents._p->contains(FIdx);
}

bool basic_block_properties_t::HasParent(void) const {
  ip_sharable_lock<ip_sharable_mutex> s_lck(Parents._mtx);

  if (!Parents._p)
    return false;

  return !Parents._p->empty();
}

void basic_block_properties_t::AddParent(function_index_t FIdx, jv_t &jv) {
  ip_func_index_set Idxs(jv.get_allocator());

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

void basic_block_properties_t::GetParents(func_index_set &out) const {
  ip_sharable_lock<ip_sharable_mutex> s_lck(Parents._mtx);

  if (!Parents._p)
    return;

  const ip_func_index_set &parents = *Parents._p;
  out.insert(parents.begin(), parents.end());
}

bool basic_block_properties_t::insertDynTarget(binary_index_t ThisBIdx,
                                               const dynamic_target_t &X,
                                               jv_t &jv) {
  function_of_target(X, jv).Callers.emplace(ThisBIdx, Term.Addr);
  return DynTargets.insert(X);
}

}
