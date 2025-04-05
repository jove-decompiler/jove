#pragma once
#include "jove/jove.h"

namespace jove {

struct an_infinite_loop_exception {};

//
// this code is for moving past NONEs.
//
template <bool MT>
static inline void fallthru(jv_base_t<MT> &jv,
                            binary_index_t BIdx,
                            basic_block_index_t BBIdx,
std::function<void(const basic_block_properties_t &, basic_block_index_t)> on_block = [](const basic_block_properties_t &, basic_block_index_t) -> void {}) {
  auto &b = jv.Binaries.at(BIdx);
  auto &ICFG = b.Analysis.ICFG;

  std::reference_wrapper<const basic_block_properties_t> the_bbprop =
      ICFG[basic_block_of_index(BBIdx, b)];

  basic_block_index_t BBIdxSav = BBIdx;
  for ((void)({
         const basic_block_properties_t &bbprop = the_bbprop.get();

         if constexpr (MT) {
           if (!bbprop.pub.is.load(std::memory_order_acquire))
             (void)bbprop.pub.shared_access<MT>();
         }
         bbprop.lock_sharable<MT>(); /* don't change on us */

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

         basic_block_t newbb = basic_block_of_index(BBIdx, b);
         const basic_block_properties_t &new_bbprop = ICFG[newbb];
         the_bbprop = new_bbprop;

         if constexpr (MT) {
           if (!new_bbprop.pub.is.load(std::memory_order_acquire))
             bbprop_t::pub_t::shared_lock_guard<MT>(new_bbprop.pub.mtx);
         }
         new_bbprop.lock_sharable<MT>(); /* don't change on us */

#if 0
         on_block(new_bbprop, BBIdx);
#endif
         0;
       })) {
    basic_block_t bb = basic_block_of_index(BBIdx, b);
    const basic_block_properties_t &bbprop = the_bbprop.get();

    const auto Addr = bbprop.Addr;
    const auto Size = bbprop.Size;
    const auto TermType = bbprop.Term.Type;

    if (TermType == TERMINATOR::NONE) {
      if (unlikely(ICFG.template out_degree<false>(bb) == 0)) {
        assert(false && "cant proceed past NONE");
        abort();
      }

      basic_block_index_t NewRes =
          index_of_basic_block(ICFG, ICFG.template adjacent_front<false>(bb));

      BBIdx = NewRes;
      continue;
    }

    bbprop_t::shared_lock_guard<MT> s_lck_bb(
        bbprop.mtx, boost::interprocess::accept_ownership);

    on_block(bbprop, basic_block_of_index(BBIdx, b));
    return;
  }
}

}
