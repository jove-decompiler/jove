#include "tool.h"
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
    __builtin_memset(&jv.FIdxSetsMtx, 0, sizeof(jv.FIdxSetsMtx));
    __builtin_memset(&jv.hash_to_binary_mtx, 0, sizeof(jv.hash_to_binary_mtx));
    __builtin_memset(&jv.cached_hashes_mtx, 0, sizeof(jv.cached_hashes_mtx));
    __builtin_memset(&jv.name_to_binaries_mtx, 0, sizeof(jv.name_to_binaries_mtx));
    __builtin_memset(&jv.Binaries._mtx, 0, sizeof(jv.Binaries._mtx));

    for (unsigned i = 0; i < jv.Binaries._deque.size(); ++i) {
      binary_t &b = jv.Binaries._deque.at(i);

      __builtin_memset(&b.bbmap_mtx, 0, sizeof(b.bbmap_mtx));
      __builtin_memset(&b.na_bbmap_mtx, 0, sizeof(b.na_bbmap_mtx));
      __builtin_memset(&b.Analysis.Functions._mtx, 0, sizeof(b.Analysis.Functions._mtx));
    }
  } else {
    try {
      jv.FIdxSetsMtx.unlock();
      jv.hash_to_binary_mtx.unlock();
      jv.cached_hashes_mtx.unlock();
      jv.name_to_binaries_mtx.unlock();

      jv.Binaries._mtx.unlock();

      for_each_binary(std::execution::par_unseq, jv, [&](binary_t &b) {
        b.bbmap_mtx.unlock();
        b.na_bbmap_mtx.unlock();
        b.Analysis.Functions._mtx.unlock();
      });
    } catch (...) {
      WithColor::error() << "unlocking failed!\n";
      return 1;
    }
  }

  return 0;
}

}
