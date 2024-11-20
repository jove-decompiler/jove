#include "tool.h"
#include <iostream>
#include <unistd.h>
#include <llvm/Support/WithColor.h>

namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

struct UnlockTool : public JVTool<ToolKind::Standard> {
  int Run(void) override;
};

JOVE_REGISTER_TOOL("unlock", UnlockTool);

int UnlockTool::Run(void) {
  WithColor::warning()
      << "this is an unsafe operation meant only to be used as a last resort. "
         "Are you sure you wish to proceed?\n";

  if (::isatty(STDIN_FILENO)) {
    HumanOut() << "Press Enter to confirm...\n";
    HumanOut().flush();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  } else {
    HumanOut() << "Standard input is not a TTY, skipping confirmation.\n";
  }

  __builtin_memset(&jv.FIdxSetsMtx, 0, sizeof(jv.FIdxSetsMtx));
  jv.Binaries.__force_reset_access();
  std::for_each(
      std::execution::par_unseq,
      jv.Binaries._deque.begin(),
      jv.Binaries._deque.end(), [&](binary_t &b) {
	__builtin_memset(&b.bbmap_mtx, 0, sizeof(b.bbmap_mtx));
        b.Analysis.ICFG.__force_reset_access();
        b.Analysis.Functions.__force_reset_access();

        auto &ICFG = b.Analysis.ICFG;
	auto it_pair = boost::vertices(ICFG._adjacency_list);
	std::for_each(std::execution::par_unseq,
		      it_pair.first,
		      it_pair.second, [&](basic_block_t bb) {
			__builtin_memset(&ICFG._adjacency_list[bb].mtx, 0,
					 sizeof(ICFG._adjacency_list[bb].mtx));
			__builtin_memset(&ICFG._adjacency_list[bb].Parents._mtx, 0,
					 sizeof(ICFG._adjacency_list[bb].Parents._mtx));
		      });
      });

  return 0;
}

}
