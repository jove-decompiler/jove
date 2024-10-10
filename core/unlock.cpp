#include "unlock.h"

namespace jove {

void forcefully_unlock(jv_t &jv) {
  __builtin_memset(&jv.FIdxSetsMtx, 0, sizeof(jv.FIdxSetsMtx));
  __builtin_memset(&jv.hash_to_binary_mtx, 0, sizeof(jv.hash_to_binary_mtx));
  __builtin_memset(&jv.cached_hashes_mtx, 0, sizeof(jv.cached_hashes_mtx));
  __builtin_memset(&jv.name_to_binaries_mtx, 0, sizeof(jv.name_to_binaries_mtx));
  __builtin_memset(&jv.Binaries._mtx, 0, sizeof(jv.Binaries._mtx));
  std::for_each(
      std::execution::par_unseq,
      jv.Binaries._deque.begin(),
      jv.Binaries._deque.end(), [&](binary_t &b) {
	__builtin_memset(&b.bbmap_mtx, 0, sizeof(b.bbmap_mtx));
	__builtin_memset(&b.Analysis.ICFG._mtx, 0, sizeof(b.Analysis.ICFG._mtx));
	__builtin_memset(&b.Analysis.Functions._mtx, 0, sizeof(b.Analysis.Functions._mtx));

	auto &ICFG = b.Analysis.ICFG;
	auto it_pair = boost::vertices(ICFG._adjacency_list);
	std::for_each(std::execution::par_unseq,
		      it_pair.first,
		      it_pair.second, [&](basic_block_t bb) {
			__builtin_memset(&ICFG._adjacency_list[bb].Parents._mtx, 0,
					 sizeof(ICFG._adjacency_list[bb].Parents._mtx));
		      });
      });
}

}
