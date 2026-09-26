#pragma once
#include "jove/jove.h"

namespace jove {

struct infinite_loop_exception {};

template <bool DoNotGoFurther, bool InfiniteLoopThrow, bool MT, bool MinSize,
          unsigned Verbosity = 0>
inline std::pair<basic_block_index_t, bool>
StraightLineGo(binary_base_t<MT, MinSize> &b,
               basic_block_index_t Res,
               taddr_t GoNoFurther = 0,
    std::function<basic_block_index_t(bbprop_t &, basic_block_index_t)> on_final_block = [](bbprop_t &, basic_block_index_t Res) -> basic_block_index_t { return Res; },
    std::function<void(bbprop_t &, basic_block_index_t)> on_block = [](bbprop_t &, basic_block_index_t) -> void {}) {
  using bb_t = binary_base_t<MT, MinSize>::bb_t;

  auto &ICFG = b.Analysis.ICFG;

  std::reference_wrapper<bbprop_t> the_bbprop =
      ICFG[basic_block_of_index(Res, b)];

  basic_block_index_t ResSav = Res;
  for ((void)({
         bbprop_t &bbprop = the_bbprop.get();

         if constexpr (MT) {
           if (!bbprop.pub.is.test(boost::memory_order_acquire))
             (void)bbprop.pub.shared_access<MT>();
         }
         bbprop.lock_sharable<MT>(); /* don't change on us */

         on_block(bbprop, Res);
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
         if (unlikely(ResSav == Res)) {
           if constexpr (InfiniteLoopThrow)
             throw infinite_loop_exception();
           else
             return std::make_pair(invalid_basic_block_index, false);
         }

         ResSav = Res;

         bb_t newbb = basic_block_of_index(Res, b);
         bbprop_t &new_bbprop = ICFG[newbb];
         the_bbprop = new_bbprop;

         if constexpr (MT) {
           if (!new_bbprop.pub.is.test(boost::memory_order_acquire))
             bbprop_t::pub_t::shared_lock_guard<MT>(new_bbprop.pub.mtx);
         }
         new_bbprop.lock_sharable<MT>(); /* don't change on us */

         on_block(new_bbprop, Res);
         0;
       })) {
    bb_t bb = basic_block_of_index(Res, b);
    bbprop_t &bbprop = the_bbprop.get();

    const auto Addr = bbprop.Addr;
    const auto Size = bbprop.Size;
    const auto TermType = bbprop.Term.Type;

    if constexpr (DoNotGoFurther) {
      if (Addr == GoNoFurther ||
          /* the following assumes that GoNoFurther sits cleanly in the block.
           * to verify this, we'd have to disassemble the instructions.
           *
           * NOTE: this happens to "resolve" a problem encountered with the
           * trace output, where an invalid IP follows a twirl. i.e., given the
           * code:
           *
           * 18d70:       f3 0f 1e fb             endbr32
           * 18d74:       e8 00 00 00 00          call   18d79
           * 18d79:       58                      pop    %eax
           * 18d7a:       05 23 b2 ff ff          add    $0xffffb223,%eax
           * 18d7f:       8b 80 38 00 00 00       mov    0x38(%eax),%eax
           *
           * we might have the following sequence:
           *
           *   on_ip(0x18d70);
           *   on_ip(0x18d76);  // <-- WTF, middle of twirl instruction
           *
           * this has been confirmed to confuse the hell out of ptxed.
           *
           **/
          unlikely(GoNoFurther >= Addr && GoNoFurther < Addr + Size)) {
        bbprop_t::shared_lock_guard<MT> s_lck_bb(
            bbprop.mtx, boost::interprocess::accept_ownership);
        return std::make_pair(
            on_final_block(bbprop, basic_block_of_index(Res, b)), true);
      }
    }

    switch (TermType) {
    default:
      break;
    case TERMINATOR::UNCONDITIONAL_JUMP:
    case TERMINATOR::NONE: {
      if (unlikely(ICFG.template out_degree<false>(bb) == 0)) {
#if 0
        if constexpr (IsVerbose())
          fprintf(
              stderr, "cant proceed past NONE @ %s+%" PRIx64 " [size=%u] %s\n",
              b.Name.c_str(), static_cast<uint64_t>(Addr),
              static_cast<unsigned>(Size), description_of_terminator(TermType));
#endif
        break;
      }

      basic_block_index_t NewRes =
          index_of_basic_block(ICFG, ICFG.template adjacent_front<false>(bb));

      Res = NewRes;
      continue;
    }
    case TERMINATOR::CALL: {
      function_index_t CalleeIdx = bbprop.Term._call.Target;
      if (unlikely(!is_function_index_valid(CalleeIdx)))
        break;

      basic_block_index_t EntryBBIdx = b.Analysis.Functions.at(CalleeIdx).Entry;
      if (!unlikely(is_basic_block_index_valid(EntryBBIdx))) {
#if 0
        if constexpr (IsVerbose())
          fprintf(stderr, "cant proceed past CALL @ %s+%" PRIx64 "\n",
                  b.Name.c_str(), static_cast<uint64_t>(Addr));
#endif
        break;
      }
      Res = EntryBBIdx;
      assert(is_basic_block_index_valid(Res));
      continue;
    }
    case TERMINATOR::CONDITIONAL_JUMP:
#if defined(TARGET_X86_64) || defined(TARGET_I386)
      if (bbprop.Term._conditional_jump.String) {
        //
        // ┌─────────────────────────────────────┐
        // │                                     │ ───┐
        // │ rep  stosq qword ptr es:[rdi], rax  │    │
        // │                                     │ ◀──┘
        // └─────────────────────────────────────┘
        //
        // there are no TNT packets for this "single-instruction" loop. we just
        // need to move past it.
        //
        assert(ICFG.template out_degree<false>(bb) == 2);
        auto succ = ICFG.template adjacent_n<2, false>(bb);
        if (succ[0] == bb) {
          Res = index_of_basic_block(ICFG, succ[1]);
        } else {
          assert(succ[1] == bb);
          Res = index_of_basic_block(ICFG, succ[0]);
        }
        continue;
      }
#endif
      break;
    }

    bbprop_t::shared_lock_guard<MT> s_lck_bb(
        bbprop.mtx, boost::interprocess::accept_ownership);
    return std::make_pair(on_final_block(bbprop, basic_block_of_index(Res, b)),
                          false);
  }

  abort();
}


}
