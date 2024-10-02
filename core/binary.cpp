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
    ip_sharable_lock<ip_upgradable_mutex> s_lck_bbmap(this->bbmap_mtx);
    ip_upgradable_lock<ip_upgradable_mutex> u_lck_ICFG(this->Analysis.ICFG_mtx);

    basic_block_t bb = basic_block_at_address(TermAddr, *this);

    if (!IsAmbiguousIndirectJump(ICFG, bb))
      return false;

    SuccAddrVec.reserve(boost::out_degree(bb, ICFG));

    icfg_t::adjacency_iterator succ_it, succ_it_end;
    for (std::tie(succ_it, succ_it_end) = boost::adjacent_vertices(bb, ICFG);
         succ_it != succ_it_end; ++succ_it)
      SuccAddrVec.push_back(ICFG[*succ_it].Addr);

    ip_scoped_lock<ip_upgradable_mutex> e_lck_ICFG(boost::move(u_lck_ICFG));

    boost::clear_out_edges(bb, ICFG); /* ambiguous no more */
  }

  std::vector<function_index_t> SuccFIdxVec;
  SuccFIdxVec.resize(SuccAddrVec.size());
  std::transform(SuccAddrVec.begin(),
                 SuccAddrVec.end(), SuccFIdxVec.begin(),
                 [&](taddr_t Addr) -> function_index_t {
                   function_index_t res = E.explore_function(*this, Bin, Addr);
                   assert(is_function_index_valid(res));
                   return res;
                 });

  {
    ip_sharable_lock<ip_upgradable_mutex> s_lck_bbmap(this->bbmap_mtx);

    basic_block_t bb = basic_block_at_address(TermAddr, *this);
    auto &bbprop = this->prop(bb);

    for (function_index_t FIdx : SuccFIdxVec)
      bbprop.insertDynTarget(index_of_binary(*this, jv),
                             {index_of_binary(*this, jv), FIdx}, jv);
  }

  return true;
}

}
