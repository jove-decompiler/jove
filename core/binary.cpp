#include "jove/jove.h"

namespace jove {

void binary_t::InvalidateBasicBlockAnalyses(void) {
  auto it_pair = boost::vertices(Analysis.ICFG);
  for (auto it = it_pair.first; it != it_pair.second; ++it)
    Analysis.ICFG[*it].InvalidateAnalysis();
}

void binary_t::Analysis_t::addSymDynTarget(const std::string &sym,
                                           dynamic_target_t X) {
  ip_string ips(Functions.get_allocator());
  to_ips(ips, sym);
  typedef std::pair<const ip_string, ip_dynamic_target_set> map_value_type;
  ip_dynamic_target_set Y(Functions.get_allocator());
  Y.insert(X);
  map_value_type z(ips, Y);

  SymDynTargets.insert(z);
}

void binary_t::Analysis_t::addRelocDynTarget(uint64_t A, dynamic_target_t X) {
  typedef std::pair<const uint64_t, ip_dynamic_target_set> map_value_type;
  ip_dynamic_target_set Y(Functions.get_allocator());
  Y.insert(X);
  map_value_type z(A, Y);
  RelocDynTargets.insert(z);
}

void binary_t::Analysis_t::addIFuncDynTarget(uint64_t A, dynamic_target_t X) {
  typedef std::pair<const uint64_t, ip_dynamic_target_set> map_value_type;
  ip_dynamic_target_set Y(Functions.get_allocator());
  Y.insert(X);
  map_value_type z(A, Y);
  IFuncDynTargets.insert(z);
}

}
