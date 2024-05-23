#include "jove/jove.h"

namespace jove {

void binary_t::InvalidateBasicBlockAnalyses(void) {
  for_each_function_in_binary(std::execution::par_unseq, *this,
                              [&](function_t &f) { f.InvalidateAnalysis(); });
}

void binary_t::Analysis_t::addSymDynTarget(const std::string &sym,
                                           dynamic_target_t X) {
  ip_string ips(Functions.get_allocator());
  to_ips(ips, sym);

  auto it = SymDynTargets.find(ips);
  if (it == SymDynTargets.end())
    it = SymDynTargets.emplace(ips, ip_dynamic_target_set(Functions.get_allocator())).first;

  (*it).second.insert(X);
}

void binary_t::Analysis_t::addRelocDynTarget(uint64_t A, dynamic_target_t X) {
  auto it = RelocDynTargets.find(A);
  if (it == RelocDynTargets.end())
    it = RelocDynTargets.emplace(A, ip_dynamic_target_set(Functions.get_allocator())).first;

  (*it).second.insert(X);
}

void binary_t::Analysis_t::addIFuncDynTarget(uint64_t A, dynamic_target_t X) {
  auto it = IFuncDynTargets.find(A);
  if (it == IFuncDynTargets.end())
    it = IFuncDynTargets.emplace(A, ip_dynamic_target_set(Functions.get_allocator())).first;

  (*it).second.insert(X);
}

}
