#include "explore.h"
#include "B.h"

namespace jove {

template <bool MT>
void binary_base_t<MT>::InvalidateBasicBlockAnalyses(void) {
  for_each_function_in_binary(std::execution::par_unseq, *this,
                              [&](function_t &f) { f.InvalidateAnalysis(); });
}

template <bool MT>
bool binary_base_t<MT>::FixAmbiguousIndirectJump(taddr_t TermAddr,
                                                 explorer_t<MT> &E,
                                                 llvm::object::Binary &Bin,
                                                 jv_file_t &jv_file,
                                                 jv_base_t<MT> &jv) {
  std::vector<taddr_t> SuccAddrVec;

  basic_block_t bb;

  auto &ICFG = this->Analysis.ICFG;
  {
    auto s_lck_bbmap = this->BBMap.shared_access();

    bb = basic_block_at_address(TermAddr, *this);

    if (!IsAmbiguousIndirectJump(ICFG, bb))
      return false;

    auto e_lck = ICFG[bb].template exclusive_access<MT>();

    icfg_t::adjacency_iterator succ_it, succ_it_end;
    std::tie(succ_it, succ_it_end) = ICFG.adjacent_vertices(bb);

    SuccAddrVec.resize(ICFG.template out_degree<false>(bb));
    std::transform(
        succ_it,
        succ_it_end, SuccAddrVec.begin(),
        [&](basic_block_t bb) -> taddr_t { return ICFG.at(bb).Addr; });
  }

  std::vector<function_index_t> SuccFIdxVec;
  SuccFIdxVec.resize(SuccAddrVec.size());
  std::transform(std::execution::seq /* TODO par_unseq */,
                 SuccAddrVec.begin(),
                 SuccAddrVec.end(), SuccFIdxVec.begin(),
                 [&](taddr_t Addr) -> function_index_t {
                   function_index_t res = E.explore_function(*this, Bin, Addr);
                   assert(is_function_index_valid(res));
                   return res;
                 });

  {
    auto s_lck_bbmap = this->BBMap.shared_access();

    ICFG.template clear_out_edges<MT>(bb); /* ambiguous no more */

    auto &bbprop = ICFG[basic_block_at_address(TermAddr, *this)];
    for (function_index_t FIdx : SuccFIdxVec) /* TODO par_unseq */
      bbprop.insertDynTarget(index_of_binary(*this, jv),
                             {index_of_binary(*this, jv), FIdx}, jv_file, jv);
  }

  ICFG[bb].InvalidateAnalysis(jv, *this);

  return true;
}

template struct binary_base_t<false>;
template struct binary_base_t<true>;

}
