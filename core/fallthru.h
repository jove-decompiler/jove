#pragma once
#include "jove/jove.h"

namespace jove {

//
// this code is for moving past NONEs.
//
template <typename Result, bool MT, bool MinSize>
static inline Result fallthru(
    jv_base_t<MT, MinSize> &jv,
    binary_index_t BIdx,
    basic_block_index_t BBIdx,
    std::function<Result(bbprop_t &, basic_block_index_t)> on_block) {
  binary_base_t<MT, MinSize> &b = jv.Binaries.at(BIdx);
  auto &ICFG = b.Analysis.ICFG;

  std::reference_wrapper<bbprop_t> the_bbprop =
      ICFG[basic_block_of_index(BBIdx, b)];

  basic_block_index_t BBIdxSav = BBIdx;
  for ((void)({
         bbprop_t &bbprop = the_bbprop.get();

         if constexpr (MT) {
           if (!bbprop.pub.is.test(boost::memory_order_acquire))
             bbprop.pub.template shared_access<MT>();
         }
         bbprop.template lock_sharable<MT>(); /* don't change on us */

         0;
       });
       ; (void)({
         the_bbprop.get().mtx.unlock_sharable();

         BBIdxSav = BBIdx;

         auto newbb = basic_block_of_index(BBIdx, b);
         bbprop_t &new_bbprop = ICFG[newbb];
         the_bbprop = new_bbprop;

         if constexpr (MT) {
           if (!new_bbprop.pub.is.test(boost::memory_order_acquire))
             bbprop_t::pub_t::template shared_lock_guard<MT>(
                 new_bbprop.pub.mtx);
         }
         new_bbprop.template lock_sharable<MT>(); /* don't change on us */

         0;
       })) {
    auto bb = ICFG.vertex(BBIdx);
    bbprop_t &bbprop = the_bbprop.get();

    if (bbprop.Term.Type == TERMINATOR::NONE) {
      if (unlikely(ICFG.template out_degree<false>(bb) == 0)) {
        assert(false && "cant proceed past NONE");
        abort();
      }

      basic_block_index_t NewRes =
          ICFG.index(ICFG.template adjacent_front<false>(bb));

      BBIdx = NewRes;
      continue;
    }

    bbprop_t::shared_lock_guard<MT> s_lck_bb(
        bbprop.mtx, boost::interprocess::accept_ownership);

    return on_block(bbprop, ICFG.vertex(BBIdx));
  }
}
}
