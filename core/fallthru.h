#pragma once
#include "jove/jove.h"

namespace jove {

struct an_infinite_loop_exception {};

//
// this code is for moving past NONEs.
//
template <bool MT, bool MinSize>
static inline void fallthru(
    jv_base_t<MT, MinSize> &jv,
    binary_index_t BIdx,
    basic_block_index_t BBIdx,
    std::function<void(const bbprop_t &, basic_block_index_t)> on_block = [](const bbprop_t &, basic_block_index_t) -> void {}) {
  binary_base_t<MT, MinSize> &b = jv.Binaries.at(BIdx);
  auto &ICFG = b.Analysis.ICFG;

  std::reference_wrapper<const bbprop_t> the_bbprop =
      ICFG[basic_block_of_index(BBIdx, b)];

  basic_block_index_t BBIdxSav = BBIdx;
  for ((void)({
         const bbprop_t &bbprop = the_bbprop.get();

         if constexpr (AreWeMT) {
           if (!bbprop.pub.is.load(std::memory_order_acquire))
             bbprop.pub.template shared_access<AreWeMT>();
         }
         bbprop.template lock_sharable<AreWeMT>(); /* don't change on us */

#if 0
         on_block(bbprop, BBIdx);
#endif
         0;
       });
       ; (void)({
         the_bbprop.get().mtx.unlock_sharable();

         //
         // cycle detection: the code might infinitely loop. FIXME
         //
         // an example seen in the wild is at the end of start_thread() in
         // glibc/nptl/pthread_create.c...
         //
         // while (1)
         //   INTERNAL_SYSCALL_CALL (exit, 0);
         //
         if (unlikely(BBIdxSav == BBIdx)) {
           throw an_infinite_loop_exception();
         }

         BBIdxSav = BBIdx;

         auto newbb = basic_block_of_index(BBIdx, b);
         const bbprop_t &new_bbprop = ICFG[newbb];
         the_bbprop = new_bbprop;

         if constexpr (AreWeMT) {
           if (!new_bbprop.pub.is.load(std::memory_order_acquire))
             bbprop_t::pub_t::template shared_lock_guard<AreWeMT>(
                 new_bbprop.pub.mtx);
         }
         new_bbprop.template lock_sharable<AreWeMT>(); /* don't change on us */

#if 0
         on_block(new_bbprop, BBIdx);
#endif
         0;
       })) {
    auto bb = ICFG.vertex(BBIdx);
    const bbprop_t &bbprop = the_bbprop.get();

    const auto Addr = bbprop.Addr;
    const auto Size = bbprop.Size;
    const auto TermType = bbprop.Term.Type;

    if (TermType == TERMINATOR::NONE) {
      if (unlikely(ICFG.template out_degree<false>(bb) == 0)) {
        assert(false && "cant proceed past NONE");
        abort();
      }

      basic_block_index_t NewRes =
          ICFG.index(ICFG.template adjacent_front<false>(bb));

      BBIdx = NewRes;
      continue;
    }

    bbprop_t::shared_lock_guard<AreWeMT> s_lck_bb(
        bbprop.mtx, boost::interprocess::accept_ownership);

    on_block(bbprop, ICFG.vertex(BBIdx));
    return;
  }
}
}
