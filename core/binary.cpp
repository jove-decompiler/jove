#include "explore.h"
#include "B.h"

namespace jove {

template <bool MT>
void binary_base_t<MT>::InvalidateBasicBlockAnalyses(void) {
  for_each_function_in_binary(std::execution::par_unseq, *this,
                              [&](function_t &f) { f.InvalidateAnalysis(); });
}

template <bool MT>
bool binary_base_t<MT>::FixAmbiguousIndirectJump(taddr_t TermAddr, explorer_t &E,
                                                 llvm::object::Binary &Bin,
                                                 jv_base_t<MT> &jv) {
  std::vector<taddr_t> SuccAddrVec;

  auto &ICFG = this->Analysis.ICFG;
  {
    auto s_lck_bbmap = this->bbmap_shared_access();

    basic_block_t bb = basic_block_at_address(TermAddr, *this);

    if (!IsAmbiguousIndirectJump(ICFG, bb))
      return false;

    ip_scoped_lock<ip_sharable_mutex> e_lck(ICFG.at(bb).mtx);

    icfg_t::adjacency_iterator succ_it, succ_it_end;
    std::tie(succ_it, succ_it_end) = ICFG.adjacent_vertices(bb);

    SuccAddrVec.resize(ICFG.template out_degree<false>(bb));
    std::transform(
        succ_it,
        succ_it_end, SuccAddrVec.begin(),
        [&](basic_block_t bb) -> taddr_t { return ICFG.at(bb).Addr; });

    ICFG.template clear_out_edges<false>(bb); /* ambiguous no more */
  }

  std::vector<function_index_t> SuccFIdxVec;
  SuccFIdxVec.resize(SuccAddrVec.size());
  std::transform(std::execution::seq /* par_unseq */,
                 SuccAddrVec.begin(),
                 SuccAddrVec.end(), SuccFIdxVec.begin(),
                 [&](taddr_t Addr) -> function_index_t {
                   function_index_t res = E.explore_function(*this, Bin, Addr);
                   assert(is_function_index_valid(res));
                   return res;
                 });

  {
    auto s_lck_bbmap = this->bbmap_shared_access();

    auto &bbprop = ICFG[basic_block_at_address(TermAddr, *this)];
    for (function_index_t FIdx : SuccFIdxVec)
      bbprop.insertDynTarget(index_of_binary(*this, jv),
                             {index_of_binary(*this, jv), FIdx}, jv);
  }

  return true;
}

template struct binary_base_t<false>;
template struct binary_base_t<true>;

}
