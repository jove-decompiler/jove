#include "explore.h"
#include "B.h"

namespace jove {

void binary_t::InvalidateBasicBlockAnalyses(void) {
  for_each_function_in_binary(std::execution::par_unseq, *this,
                              [&](function_t &f) { f.InvalidateAnalysis(); });
}

bool binary_t::FixAmbiguousIndirectJump(taddr_t TermAddr, explorer_t &E,
                                        llvm::object::Binary &Bin, jv_t &jv) {
  std::vector<taddr_t> SuccAddrVec;

  auto &ICFG = this->Analysis.ICFG;
  {
    ip_sharable_lock<ip_sharable_mutex> s_lck_bbmap(this->bbmap_mtx);

    basic_block_t bb = basic_block_at_address(TermAddr, *this);

    if (!IsAmbiguousIndirectJump(ICFG, bb))
      return false;

    ip_scoped_lock<ip_sharable_mutex> e_lck(ICFG.at(bb).mtx);

    icfg_t::adjacency_iterator succ_it, succ_it_end;
    std::tie(succ_it, succ_it_end) = ICFG.adjacent_vertices(bb);

    SuccAddrVec.resize(ICFG.out_degree<false>(bb));
    std::transform(
        succ_it,
        succ_it_end, SuccAddrVec.begin(),
        [&](basic_block_t bb) -> taddr_t { return ICFG.at(bb).Addr; });

    ICFG.clear_out_edges<false>(bb); /* ambiguous no more */
  }

  std::vector<function_index_t> SuccFIdxVec;
  SuccFIdxVec.resize(SuccAddrVec.size());
  std::transform(std::execution::par_unseq,
                 SuccAddrVec.begin(),
                 SuccAddrVec.end(), SuccFIdxVec.begin(),
                 [&](taddr_t Addr) -> function_index_t {
                   function_index_t res = E.explore_function(*this, Bin, Addr);
                   assert(is_function_index_valid(res));
                   return res;
                 });

  {
    ip_sharable_lock<ip_sharable_mutex> s_lck_bbmap(this->bbmap_mtx);

    auto &bbprop = ICFG[basic_block_at_address(TermAddr, *this)];
    for (function_index_t FIdx : SuccFIdxVec)
      bbprop.insertDynTarget(index_of_binary(*this, jv),
                             {index_of_binary(*this, jv), FIdx}, jv);
  }

  return true;
}

}
