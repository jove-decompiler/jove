#include "tool.h"
#include "unlock.h"
#include <llvm/Support/WithColor.h>

namespace cl = llvm::cl;

using llvm::WithColor;

namespace jove {

class UnlockTool : public JVTool<ToolKind::Standard> {
  struct Cmdline {
  cl::opt<bool> Force;
  cl::alias ForceAlias;

  Cmdline(llvm::cl::OptionCategory &JoveCategory)
      : Force("force", cl::desc("Forcefully reset locks."),
              cl::cat(JoveCategory)),
        ForceAlias("f", cl::desc("Alias for --force."), cl::aliasopt(Force),
                   cl::cat(JoveCategory)) {}
  } opts;

public:
  UnlockTool() : opts(JoveCategory) {}

  int Run(void) override;
};

JOVE_REGISTER_TOOL("unlock", UnlockTool);

int UnlockTool::Run(void) {
  if (opts.Force) {
    forcefully_unlock(jv);
  } else {
    try {
      jv.FIdxSetsMtx.unlock();
      jv.hash_to_binary_mtx.unlock();
      jv.cached_hashes_mtx.unlock();
      jv.name_to_binaries_mtx.unlock();
      jv.Binaries._mtx.unlock();
      std::for_each(std::execution::par_unseq,
                    jv.Binaries._deque.begin(),
                    jv.Binaries._deque.end(), [&](binary_t &b) {
                      b.bbmap_mtx.unlock();
                      b.Analysis.ICFG_mtx.unlock();
                      b.Analysis.Functions._mtx.unlock();

                      auto &ICFG = b.Analysis.ICFG;
                      auto it_pair = boost::vertices(ICFG);
                      std::for_each(std::execution::par_unseq, it_pair.first,
                                    it_pair.second, [&](basic_block_t bb) {
                                      ICFG[bb].Parents._mtx.unlock();
                                    });
                    });
    } catch (...) {
      WithColor::error() << "unlocking failed!\n";
      return 1;
    }
  }

  return 0;
}

}
