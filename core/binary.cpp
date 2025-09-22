#include "explore.h"
#include "B.h"

namespace jove {

template <bool MT, bool MinSize>
void binary_analysis_t<MT, MinSize>::move_stuff(void) noexcept {
#ifdef JOVE_NO_TBB
  move_dyn_targets();
  move_callers();
#else
  oneapi::tbb::parallel_invoke([&](void) -> void { move_dyn_targets(); },
                               [&](void) -> void { move_callers(); });
#endif
}

template <bool MT, bool MinSize>
void binary_analysis_t<MT, MinSize>::move_dyn_targets(void) noexcept {
  using OurDynTargets_t = DynTargets_t<MT, MinSize>;
  using OtherDynTargets_t = DynTargets_t<!MT, MinSize>;

  segment_manager_t &sm = get_segment_manager();

  for_each_basic_block_in_binary(maybe_par_unseq, *this, [&](bb_t bb) {
    bbprop_t &bbprop = this->ICFG[bb];

    void *const p = bbprop.pDynTargets.load(std::memory_order_relaxed);
    if (!p)
      return;

    {
      segment_manager_t &bbprop_sm = get_segment_manager();
      assert(&bbprop_sm == &sm);
    }

    uintptr_t p_addr = reinterpret_cast<uintptr_t>(p);
    bool TheMT      = !!(p_addr & 1u);
    bool TheMinSize = !!(p_addr & 2u);
    p_addr &= ~3ULL;

    assert(TheMT == !MT);
    assert(TheMinSize == MinSize);

    OtherDynTargets_t *const pOtherDynTargets =
        reinterpret_cast<OtherDynTargets_t *>(p_addr);

    static_assert(alignof(OurDynTargets_t) >= 4);
    void *mem =
        sm.allocate_aligned(sizeof(OurDynTargets_t), alignof(OurDynTargets_t));
    assert(mem);

    uintptr_t OurPtrAddr = reinterpret_cast<uintptr_t>(
        new (mem) OurDynTargets_t(std::move(*pOtherDynTargets)));
    assert(OurPtrAddr);
    OurPtrAddr |= (MT ? 1u : 0u) | (MinSize ? 2u : 0u);

    bbprop.pDynTargets.store(reinterpret_cast<void *>(OurPtrAddr),
                             std::memory_order_relaxed);

    pOtherDynTargets->~OtherDynTargets_t();
    sm.deallocate(pOtherDynTargets);
  });
}

template <bool MT, bool MinSize>
void binary_analysis_t<MT, MinSize>::move_callers(void) noexcept {
  using OurCallers_t = Callers_t<MT, MinSize>;
  using OtherCallers_t = Callers_t<!MT, MinSize>;

  segment_manager_t &sm = get_segment_manager();

  for_each_function_in_binary(maybe_par_unseq, *this, [&](function_t &f) {
    void *const p = f.Analysis.pCallers.load(std::memory_order_relaxed);
    if (!p)
      return;

    assert(&f.Analysis.get_segment_manager() == &sm);

    uintptr_t p_addr = reinterpret_cast<uintptr_t>(p);
    bool TheMT      = !!(p_addr & 1u);
    bool TheMinSize = !!(p_addr & 2u);
    p_addr &= ~3ULL;

    assert(TheMT == !MT);
    assert(TheMinSize == MinSize);

    OtherCallers_t *const pOtherCallers =
        reinterpret_cast<OtherCallers_t *>(p_addr);

    static_assert(alignof(OurCallers_t) >= 4);
    void *mem =
        sm.allocate_aligned(sizeof(OurCallers_t), alignof(OurCallers_t));
    assert(mem);

    uintptr_t OurPtrAddr = reinterpret_cast<uintptr_t>(
        new (mem) OurCallers_t(std::move(*pOtherCallers)));
    assert(OurPtrAddr);
    OurPtrAddr |= (MT ? 1u : 0u) | (MinSize ? 2u : 0u);

    f.Analysis.pCallers.store(reinterpret_cast<void *>(OurPtrAddr),
                              std::memory_order_relaxed);

    pOtherCallers->~OtherCallers_t();
    sm.deallocate(pOtherCallers);
  });
}

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
                                           {index_of_binary(*this, jv), FIdx}, jv);
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
                                GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))>;     \
  template struct binary_analysis_t<GET_VALUE(BOOST_PP_SEQ_ELEM(1, product)),  \
                                    GET_VALUE(BOOST_PP_SEQ_ELEM(0, product))>;

BOOST_PP_SEQ_FOR_EACH_PRODUCT(DO_INSTANTIATE, (VALUES_TO_INSTANTIATE_WITH1)(VALUES_TO_INSTANTIATE_WITH2))

}
