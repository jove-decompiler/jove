#include "explore.h"
#include "B.h"

namespace jove {

template <bool MT, bool MinSize>
void binary_base_t<MT, MinSize>::InvalidateBasicBlockAnalyses(void) {
  for_each_function_in_binary(maybe_par_unseq, *this,
                              [&](function_t &f) { f.InvalidateAnalysis(); });
}

template <bool MT, bool MinSize>
bool binary_base_t<MT, MinSize>::FixAmbiguousIndirectJump(
    taddr_t TermAddr,
    explorer_t<MT, MinSize> &E,
    llvm::object::Binary &Bin,
    jv_file_t &jv_file,
    jv_base_t<MT, MinSize> &jv) {
  std::vector<taddr_t> SuccAddrVec;

  typename ip_icfg_base_t<MT>::vertex_descriptor bb;

  auto &ICFG = this->Analysis.ICFG;
  {
    auto s_lck_bbmap = this->BBMap.shared_access();

    bb = basic_block_at_address(TermAddr, *this);

    if (!IsAmbiguousIndirectJump(ICFG, bb))
      return false;

    auto e_lck = ICFG[bb].template exclusive_access<MT>();

    auto succ_it_pair = ICFG.adjacent_vertices(bb);

    SuccAddrVec.resize(ICFG.template out_degree<false>(bb));
    std::transform(
        succ_it_pair.first,
        succ_it_pair.second, SuccAddrVec.begin(),
        [&](bb_t bb) -> taddr_t { return ICFG.at(bb).Addr; });
  }

  std::vector<function_index_t> SuccFIdxVec;
  SuccFIdxVec.resize(SuccAddrVec.size());
  std::transform(std::execution::seq,
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
    std::for_each(maybe_par_unseq,
                  SuccFIdxVec.cbegin(),
                  SuccFIdxVec.cend(), [&](function_index_t FIdx) {
                    bbprop.insertDynTarget(index_of_binary(*this, jv),
                                           {index_of_binary(*this, jv), FIdx},
                                           jv_file, jv);
                  });
  }

  ICFG[bb].InvalidateAnalysis(jv, *this);

  return true;
}

#define VALUES_TO_INSTANTIATE_WITH1                                            \
    ((true))                                                                   \
    ((false))
#define VALUES_TO_INSTANTIATE_WITH2                                            \
    ((true))                                                                   \
    ((false))

#define GET_VALUE(x) BOOST_PP_TUPLE_ELEM(0, x)

#define DO_INSTANTIATE(r, product)                                             \
  template struct binary_base_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),      \
                                GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))>;

BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
