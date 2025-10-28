#include "tool.h"
#include <iostream>
#include <unistd.h>
#include <llvm/Support/FormatVariadic.h>
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

  static std::conditional_t<AreWeMT, std::mutex, std::monostate> Mtx;

#define FORCE_RESET_ACCESS(var)                                                \
  do {                                                                         \
    std::conditional_t<AreWeMT, std::unique_lock<std::mutex>, nop_t> lck(Mtx); \
                                                                               \
    if (IsVerbose())                                                           \
      HumanOut() << llvm::formatv("Unlocking {0}...\n",                        \
                                  BOOST_PP_STRINGIZE(var));                    \
    (var).__force_reset_access();                                              \
    if (IsVerbose())                                                           \
      HumanOut() << llvm::formatv("Unlocked {0}.\n",                           \
                                  BOOST_PP_STRINGIZE(var));                    \
  } while (false)

  FORCE_RESET_ACCESS(jv.Binaries);
  std::for_each(
      maybe_par_unseq,
      jv.Binaries.begin(),
      jv.Binaries.end(), [&](binary_t &b) {
        FORCE_RESET_ACCESS(b.BBMap);
        FORCE_RESET_ACCESS(b.Analysis.ICFG);
        FORCE_RESET_ACCESS(b.Analysis.Functions);

        auto it_pair = boost::vertices(b.Analysis.ICFG.container());
        std::for_each(maybe_par_unseq,
                      it_pair.first,
                      it_pair.second, [&](bb_t bb) {
                        auto &bbprop = b.Analysis.ICFG.container()[bb];

                        FORCE_RESET_ACCESS(bbprop);
                        FORCE_RESET_ACCESS(bbprop.pub);
        });
      });

  return 0;
}

}
